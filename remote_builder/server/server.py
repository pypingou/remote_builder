import argparse
import logging
import os
import subprocess
import sys
import tempfile

import rpyc
from rpyc.utils.server import ThreadedServer

from remote_builder.server import exceptions
import remote_builder.server.utils

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


def _run_command(cmd, cwd=None):
    """Run the specified command and return its stdout, stderr and returncode."""
    _log.debug(f"   Command: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=cwd,
    )
    outs, errs = proc.communicate()
    _log.debug(f"   Command finished with the code: {proc.returncode}")
    return [
        proc.returncode,
        outs.decode("utf-8").strip(),
        errs.decode("utf-8").strip(),
    ]


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
            raise exceptions.BaseRemoteBuilderError("No working directory set")

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

    def exposed_install_srpm(self, name):
        """Install the specified source rpm so we can try rebuilding it."""
        self._checks()
        filename = secure_filename(name)

        if not os.path.exists(os.path.join(self.tmpdirname.name, filename)):
            _log.info(f"Could not find the srpm: {name} to build")
            raise exceptions.BaseRemoteBuilderError(f"Could not file the file: {name}")

        _log.info(
            f"Installing source rpm {os.path.join(self.tmpdirname.name, filename)}"
        )
        cmd = [
            "rpm",
            "-iv",
            "-D",
            f"%_topdir {self.tmpdirname.name}",
            os.path.join(self.tmpdirname.name, filename),
        ]
        returncode, outs, errs = _run_command(cmd, cwd=self.tmpdirname.name)

        _log.info(
            f"Removing the original source rpm {os.path.join(self.tmpdirname.name, filename)}"
        )
        os.unlink(os.path.join(self.tmpdirname.name, filename))

        return [returncode, outs, errs]

    @needs_rpmbuild
    def exposed_build_srpm(self):
        """Build the specified source rpm."""
        self._checks()

        def retrieve_file(folder, end):
            """Browse the provided folder and find the spec files available."""
            specs = []
            for (dirpath, dirnames, filenames) in os.walk(folder):
                for filename in filenames:
                    if filename.endswith(end):
                        specs.append(os.path.join(dirpath, filename))
            return specs

        specs = retrieve_file(self.tmpdirname.name, ".spec")
        if len(specs) == 1:
            spec = specs[0]
        elif len(specs) == 0:
            raise exceptions.BaseRemoteBuilderError(
                f"No spec file found in: {self.tmpdirname.name}"
            )
        else:
            raise exceptions.BaseRemoteBuilderError(
                f"Several spec files found in: {self.tmpdirname.name}"
            )

        _log.info(f"Building rpm {os.path.join(self.tmpdirname.name, spec)}")
        cmd = [
            "rpmbuild",
            "-bs",
            os.path.join(self.tmpdirname.name, spec),
            "-D",
            f"%_topdir {self.tmpdirname.name}",
            "-D",
            "%_srcrpmdir %{_topdir}",
        ]
        returncode, outs, errs = _run_command(cmd, cwd=self.tmpdirname.name)
        _log.debug("RPM built")

        srpms = retrieve_file(self.tmpdirname.name, ".src.rpm")
        srpm = None
        if len(srpms) == 1:
            srpm = os.path.basename(srpms[0])
        elif len(srpms) == 0:
            raise exceptions.BaseRemoteBuilderError(
                f"No source rpm file found in: {self.tmpdirname.name}"
            )
        else:
            raise exceptions.BaseRemoteBuilderError(
                f"Several source rpm files found in: {self.tmpdirname.name}"
            )

        return [returncode, outs, errs, srpm]

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
        returncode, outs, errs = _run_command(cmd, cwd=self.tmpdirname.name)

        return [returncode, outs, errs]

    @needs_rpmbuild
    def exposed_build_rpm(self, name):
        """Build the RPM from the specified source RPM."""
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
        returncode, outs, errs = _run_command(cmd, cwd=self.tmpdirname.name)
        _log.debug("RPM built")

        return [returncode, outs, errs]

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
        "-p",
        "--port",
        default=18861,
        help="Port to the run the server at (detaulf to 18861)",
    )

    return parser.parse_args(args)


def main():
    """Start of the application."""
    logging.basicConfig(format="%(asctime)-20s %(levelname)-6s %(message)s")
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
