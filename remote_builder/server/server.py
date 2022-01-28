import argparse
import logging
import shutil
import subprocess
import tempfile
import os

import rpyc

import remote_builder.server.utils
from remote_builder.server import exceptions

_log = logging.getLogger(__name__)


def needs_rpmbuild(func):
    def inner(*args):
        subprocess.check_output(["rpm", "-q", "rpm-build"])
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

    @needs_rpmbuild
    def exposed_build_srpm(self, name):
        """Build the specified source rpm."""
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
        _log.debug("Dependencies installed")

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

        return tuple([outs, errs, proc.returncode])

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


if __name__ == "__main__":
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    _log.setLevel(logging.DEBUG)

    from rpyc.utils.server import ThreadedServer

    t = ThreadedServer(RemoteBuilderService, port=18861)
    t.start()
    _log.info("Server running")