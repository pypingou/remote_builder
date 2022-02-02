import argparse
import logging
import json
import shutil
import subprocess
import sys
import tempfile
import os

import rpyc
from rpyc.utils.server import ThreadedServer

import remote_builder.server.utils
from remote_builder.server import exceptions
from remote_builder.server import containers

_log = logging.getLogger(__name__)


def needs_rpmbuild(func):
    def inner(*args):
        subprocess.check_output(["rpm", "-q", "rpm-build"])
        return func(*args)

    return inner


def needs_dnf_plugins(func):
    def inner(*args):
        subprocess.check_output(["rpm", "-q", "dnf-plugins-core"])
        return func(*args)

    return inner


def needs_podman(func):
    def inner(*args):
        subprocess.check_output(["rpm", "-q", "podman"])
        return func(*args)

    return inner


def secure_filename(name):
    filename = remote_builder.server.utils.secure_filename(name)
    if not filename:
        _log.info(f"Could not secure the name of {name}")
        raise exceptions.BaseRemoteBuilderError(f"Could not secure the name: {name}")
    return filename


class RemoteBuilderService(rpyc.Service):
    tempdirname = None

    def on_connect(self, conn):
        # code that runs when a connection is created
        # (to init the service, if needed)
        self._conn = conn

    def on_disconnect(self, conn):
        # code that runs after the connection has already closed
        # (to finalize the service, if needed)
        pass

    def _checks(self):
        """Performs a few checks before continuing."""
        if not self.tmpdirname:
            _log.info("No workding directory set")
            raise exceptions.BaseRemoteBuilderError(f"No working directory set")

    def exposed_create_builder(self, running_port=18861):
        """Create a podman container which will be to build the package."""
        containerfile = os.path.join(self.tmpdirname.name, "Containerfile_builder")
        _log.info(
            f"Writing down the Dockerfile for builders at {containerfile}"
        )
        with open(containerfile, "wb") as out_file:
            out_file.write(containers.BUILDER_CONTAINER.encode("utf-8"))

        _log.info("Building builder container")
        cmd = ["podman", "build", "-f", containerfile, "--rm", "-t", "rs_builder"]
        _log.debug(f"Command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdirname.name,
        )
        outs, errs = proc.communicate()
        image_id = outs.decode("utf-8").strip().split("\n")[-1]
        _log.debug(f"  Building the container finished with the code: {proc.returncode}")
        _log.info(f"Container image built: {image_id}")

        _log.info("Starting builder container")
        cmd = ["podman", "run", "-dt", "-p", f"{running_port + 1}:18861/tcp", "--rm", image_id]
        _log.debug(f"Command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdirname.name,
        )
        outs, errs = proc.communicate()
        _log.info(f"Container started: {errs.decode('utf-8')}")
        _log.debug(f"  Building the container finished with the code: {proc.returncode}")

        return [proc.returncode, outs.decode("utf-8"), running_port + 1]

    def exposed_create_workdir(self):
        """Create a temporary directory to be used as a work directory."""
        self.tmpdirname = tempfile.TemporaryDirectory(prefix="remote_builder-")
        _log.info(f"Working directory {self.tmpdirname.name} created")
        _log.debug(f"Working directory {self.tmpdirname.name} created")

    def exposed_write_srpm(self, name, stream):
        """Write the specified srpm into a temporary file."""
        self._checks()
        filename = secure_filename(name)

        _log.info(f"Writing file {os.path.join(self.tmpdirname.name, filename)}")
        with open(os.path.join(self.tmpdirname.name, filename), "wb") as out_file:
            out_file.write(stream)

        _log.info(
            f"Content of{self.tmpdirname.name} is {os.listdir(self.tmpdirname.name)}"
        )

    def exposed_clean_workdir(self):
        """Delete the temporary directory to be used as a work directory."""
        self._checks()
        _log.info(f"Cleaning up: {self.tmpdirname.name}")
        self.tmpdirname.cleanup()

    def get_rpms_paths(self):
        """Returns the list RPMs present in the temp directory."""
        rpms = []
        for (dirpath, dirnames, filenames) in os.walk(self.tmpdirname.name):
            for filename in filenames:
                print(dirpath, filename)
                if filename.endswith(".rpm"):
                    rpms.append(os.path.join(dirpath, filename))
        return rpms

    @needs_dnf_plugins
    def exposed_install_build_dependencies(self, name):
        """Install the build dependencies of the specified source rpm."""
        self._checks()
        filename = secure_filename(name)

        if not os.path.exists(os.path.join(self.tmpdirname.name, filename)):
            _log.info(f"Could not find the srpm: {name} to build")
            raise exceptions.BaseRemoteBuilderError(f"Could not file the file: {name}")

        _log.info(
            f"Installing build dependencies rpm {os.path.join(self.tmpdirname.name, filename)}"
        )
        cmd = ["dnf", "builddep", "-y", os.path.join(self.tmpdirname.name, filename)]
        _log.debug(f"Command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdirname.name,
        )
        outs, errs = proc.communicate()
        _log.debug(f"Installing dependencies finished with the code: {proc.returncode}")

        return [outs, errs, proc.returncode]

    @needs_rpmbuild
    def exposed_build_srpm(self, name):
        """Build the specified source rpm."""
        self._checks()
        filename = secure_filename(name)

        if not os.path.exists(os.path.join(self.tmpdirname.name, filename)):
            _log.info(f"Could not find the srpm: {name} to build")
            raise exceptions.BaseRemoteBuilderError(f"Could not file the file: {name}")

        _log.info(f"Building rpm {os.path.join(self.tmpdirname.name, filename)}")
        cmd = [
            "rpmbuild",
            "--rebuild",
            os.path.join(self.tmpdirname.name, filename),
            "-D",
            f"%_topdir {self.tmpdirname.name}",
            "-D",
            "%_sourcedir %{_topdir}",
            "-D",
            "%_specdir %{_topdir}",
            "-D",
            "%_srcrpmdir %{_topdir}",
            "-D",
            "%_builddir %{_topdir}",
            "-D",
            "%_rpmdir %{_topdir}",
        ]
        _log.debug(f"Command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.tmpdirname.name,
        )
        outs, errs = proc.communicate()
        _log.debug("RPM built")

        return [outs, errs, proc.returncode]

    def exposed_retrieve_rpm_lists(self, include_srpm=False):
        """Retrieve the RPMs built remotely."""
        self._checks()
        _log.info("Retrieving the list of RPMs present")
        rpms = self.get_rpms_paths()
        _log.debug(f"RPMs: {rpms}")
        output = []
        for rpm in rpms:
            rpm = rpm.replace(self.tmpdirname.name, "").lstrip("/")
            if not rpm.endswith(".src.rpm"):
                _log.debug(f"Include RPMs: {rpm}")
                output.append(rpm)
            elif include_srpm:
                _log.debug(f"Include SRPMs: {rpm}")
                output.append(rpm)
        _log.debug(f"Returning: {output}")
        return output

    def exposed_retrieve_file(self, path):
        """Retrieve the specified file in the temporary directory remotely."""
        self._checks()
        fullpath = os.path.join(self.tmpdirname.name, path)
        _log.info(f"Retrieving the file {fullpath}")
        with open(fullpath, "rb") as stream:
            return stream.read()

    @needs_podman
    def exposed_list_images(self):
        """Returns the list of image IDs for images related to remote_builder."""
        _log.info("Retrieving the list of podman images")
        cmd = ["podman", "images", "--format", "json"]
        _log.debug(f"Command: {' '.join(cmd)}")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        outs, errs = proc.communicate()
        _log.debug(f"Retrieving podman images finished with the code: {proc.returncode}")
        if proc.returncode != 0:
            return [[], errs, proc.returncode]

        data = json.loads(outs.decode("utf-8"))
        output = []
        for image in data:
            for name in image.get("Names", []):
                if "rs_builder" in name:
                    output.append(image.get("Id"))
                    break

        return [output, errs, proc.returncode]

    @needs_podman
    def exposed_clean_images(self, images):
        """Delete the images specified in the provided list."""
        _log.info(f"Deleting the podman images: {' '.join(images)}")
        outcodes = []
        for image in images:
            cmd = ["podman", "rmi", image, "-f"]
            _log.debug(f"Command: {' '.join(cmd)}")
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            proc.communicate()
            outcodes.append(proc.returncode)
            _log.debug(f"Deleting podman images {image} finished with the code: {proc.returncode}")

        return outcodes


def parse_arguments(args=None):
    """Set-up the argument parsing."""
    parser = argparse.ArgumentParser(description="Remote Builder CLI tool")

    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Increase the verbosity of the information displayed",
    )

    parser.add_argument(
        "-p", "--port",
        default=18861,
        help="Port to the run the server at (detaulf to 18861)",
    )

    return parser.parse_args(args)


def main():
    """Start of the application."""
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    _log.setLevel(logging.INFO)

    # Parse the arguments
    args = parse_arguments(sys.argv[1:])

    if args.debug:
        _log.setLevel(logging.DEBUG)

    _log.info(f"Starting server at port {args.port}")
    t = ThreadedServer(RemoteBuilderService, port=args.port)
    t.start()
    _log.info("Server running")

    return 0


if __name__ == "__main__":
    sys.exit(main())
