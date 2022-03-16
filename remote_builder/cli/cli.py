import argparse
import configparser
import itertools
import logging
from multiprocessing import Pool
import os
import subprocess
import sys
import time

import rpyc

from remote_builder.server import exceptions


_log = logging.getLogger(__name__)


_default_config = """
[container]
containerimage = quay.io/pchibon/remote_builder
[hosts]
host1 = localhost
[localhost]
type=       socket
port=       18861
timeout=    14400
"""


def _parser_rpmbuild(subparser):
    """Set up the CLI argument parser for the rpmbuild action.

    :arg subparser: an argparse subparser allowing to have action's specific
        arguments

    """
    local_parser = subparser.add_parser(
        "rpmbuild", help="Build the specified source RPM (*.src.rpm) remotely"
    )
    local_parser.add_argument("source_rpm", help="Path to the source RPM to build")
    local_parser.set_defaults(func="do_rpmbuild")


def _parser_clean_images(subparser):
    """Set up the CLI argument parser for the clean-images action.

    :arg subparser: an argparse subparser allowing to have action's specific
        arguments

    """
    local_parser = subparser.add_parser(
        "clean-images", help="Clean all the remote_builder related images on the server"
    )
    local_parser.add_argument(
        "--image",
        default=None,
        help="ID of the image to delete. If none is provided, all the images are deleted.",
    )
    local_parser.add_argument(
        "--dry-run",
        default=False,
        action="store_true",
        help="Lists the containers and images who would be deleted, don't actually delete them",
    )
    local_parser.set_defaults(func="do_clean_images")


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
        "--sequential",
        default=False,
        action="store_true",
        help="Process the different hosts sequentially instead of in parallel",
    )

    parser.add_argument(
        "--config",
        help="Configuration file to use",
    )

    parser.add_argument(
        "--host",
        default="localhost",
        help="Host of the run the server at (detaulf to localhost)",
    )

    parser.add_argument(
        "-p",
        "--port",
        default=18861,
        help="Port to the run the server at (detaulf to 18861)",
    )

    subparser = parser.add_subparsers(title="actions")

    # rpmbuild
    _parser_rpmbuild(subparser)
    # clean-images
    _parser_clean_images(subparser)

    return parser.parse_args(args)


def _validate_config(config):
    """Validate the configuration file."""

    if not config.has_section("hosts"):
        raise configparser.NoSectionErro("Configuration file has no 'hosts' section")

    if config.has_section("container"):
        options = config.options("container")
        if "containerimage" in options and "containerfile" in options:
            _log.warning(
                "Both containerimage and containerfile present in the configuration "
                "file, containerfile will be used."
            )
        elif "containerimage" not in options and "containerfile" not in options:
            raise configparser.NoOptionError(
                "Neither containerfile nor containerimage specified in the config"
            )

    for _, host in config.items("hosts"):
        if "type" not in config.options(host):
            raise configparser.NoOptionError(f"Host {host} has not 'type' option")
        if config.get(host, "type") not in ["ssh", "socket"]:
            raise configparser.NoOptionError(
                f"Host {host}'s type option is invalid, not either: ssh, socket"
            )
        if not config.get(host, "port"):
            raise configparser.NoOptionError(f"Host {host} has no port specified")
        if config.get(host, "type") == "ssh":
            if not config.get(host, "user") and not config.get(host, "keyfile"):
                raise configparser.NoOptionError(
                    f"Host {host} has no user or keyfile specified"
                )


def get_config(configfile=None):
    """Returns the ConfigParser object with the loaded configuration."""
    _log.debug("Loading the default configuration")
    config = configparser.ConfigParser()

    if configfile:
        _log.debug(f"Loading the configuration file from {configfile}")
        config.read(configfile)
    else:
        _log.debug("Loading the default configuration")
        config.read_string(_default_config)

    _validate_config(config)
    return config


class RemoteBuilder():

    config = None
    host = None
    args = None
    port = None
    conn = None
    proc = None
    remote_proc = None

    def __init__(self, config, host, args, port=None):
        self.config = config
        self.host = host
        self.args = args
        self.port = port

    def _connect(self, port=None, start_server=False):
        """Connect to the host specified in the configuration file using its information.

        In this method we allow to override the 'port' used by the server service.
        """
        self.port = port or self.port or self.config.get(self.host, "port")
        connection_type = self.config.get(self.host, "type")
        timeout = self.config.getint(self.host, "timeout", fallback=(60 * 60 * 3))  # 3h timeout
        _log.info(
            f"Connecting to {self.host}:{self.port} using {connection_type} with timeout: {timeout}"
        )

        if connection_type == "socket":
            if start_server:
                self.proc = subprocess.Popen([
                        "python3",
                        "server/server.py",
                        "--debug"
                        ],
                        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
                        env=os.environ.update(
                            {"PYTHONPATH": os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))}
                        )
                )
                time.sleep(1)
            conn = rpyc.connect(
                host=self.host,
                port=self.port,
                config={
                    "sync_request_timeout": timeout,
                },
                keepalive=True,
            )
        else:
            user = self.config.get(self.host, "user", fallback=None)
            keyfile = self.config.get(self.host, "keyfile", fallback=None)
            password = self.config.get(self.host, "password", fallback=None)
            ssh_port = self.config.getint(self.host, "ssh_port", fallback=22)
            _log.debug(
                f"Connecting via ssh as {user} using the keyfile {keyfile} and "
                f"or password: {'***' if password else password}"
            )
            from plumbum import SshMachine

            # FYI here are is the doc about this object:
            # https://plumbum.readthedocs.io/en/latest/api/machines.html#plumbum.machines.ssh_machine.SshMachine

            rem = SshMachine(
                self.host,
                user=user,
                keyfile=keyfile,
                password=password,
                port=ssh_port,
                ssh_opts=[
                    "-o UserKnownHostsFile=/dev/null",
                    "-o StrictHostKeyChecking=no",
                ],
            )
            conn = rpyc.ssh_connect(
                remote_machine=rem,
                remote_port=self.port,
                config={
                    "sync_request_timeout": timeout,
                },
            )
            if start_server:
                returncode, image_id, stderr = conn.root.install_remote_builder()
                if returncode == 0:
                    _log.info(f"{self.host.ljust(20)}    clone the remote_builder project sucessfully")
                else:
                    _log.info(f"{self.host.ljust(20)}    Failed to clone the remote_builder project")
                    return returncode

                self.remote_proc = conn.root.start_server()

        return conn

    def do_rpmbuild(self):
        """Build remotly the specified source rpm


        :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
        :arg args: the argparse object returned by ``parse_arguments()``.

        """
        _log.debug(f"{self.host.ljust(20)} source_rpm:     %s", self.args.source_rpm)

        if not os.path.exists(self.args.source_rpm):
            raise OSError("File not found: %s", self.args.source_rpm)

        self.conn.root.create_workdir()

        _log.info(f"{self.host.ljust(20)} Creating the builder container")
        returncode, image_id, stderr = self.conn.root.create_builder(
            containerfile=self.config.get("container", "containerfile", fallback=None),
            containerimage=self.config.get("container", "containerimage", fallback=None),
        )
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Container created sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to create container")
            return returncode

        _log.info(f"{self.host.ljust(20)} Starting the builder container")
        returncode, container_id, stderr, new_port = self.conn.root.start_builder(
            image_id, self.args.port
        )
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Container started sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}   Failed to start container")
            print(stderr)
            return returncode

        time.sleep(2)

        builder = self._connect(new_port)
        builder.root.create_workdir()

        srpm_filename = os.path.basename(self.args.source_rpm)

        _log.info(
            f"{self.host.ljust(20)} Uploading the source rpm:            {self.args.source_rpm}"
        )
        with open(self.args.source_rpm, "rb") as stream:
            builder.root.write_srpm(srpm_filename, stream.read())

        _log.info(
            f"{self.host.ljust(20)} Installing the source rpm:           {self.args.source_rpm}"
        )
        returncode, outs, errs = builder.root.install_srpm(srpm_filename)
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Installed SRPM sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to install the SRPM")
            print(outs)
            print(errs)
            return returncode

        _log.info(
            f"{self.host.ljust(20)} Rebuilding the source rpm:           {self.args.source_rpm}"
        )
        returncode, outs, errs, source_rpm = builder.root.build_srpm()
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Rebuilt SRPM sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to rebuild the SRPM")
            print(outs)
            print(errs)
            return returncode

        _log.info(f"{self.host.ljust(20)} Installing build dependencies of:    {source_rpm}")
        returncode, outs, errs = builder.root.install_build_dependencies(source_rpm)
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Dependencies installed sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to install dependencies")
            print(outs)
            print(errs)
            return returncode

        _log.info(f"{self.host.ljust(20)} Building the RPM from:               {source_rpm}")
        returncode, outs, errs = builder.root.build_rpm(source_rpm)
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    RPM built sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to build the RPMs")
        _log.debug(f"{self.host.ljust(20)} Return code: {returncode}")
        with open(f"{srpm_filename}.{self.host}.stdout", "w") as stream:
            stream.write(outs)
        with open(f"{srpm_filename}.{self.host}.stderr", "w") as stream:
            stream.write(errs)
        _log.info(
            f"{self.host.ljust(20)}    stdout log written in: {srpm_filename}.{self.host}.stdout"
        )
        _log.info(
            f"{self.host.ljust(20)}    stderr log written in: {srpm_filename}.{self.host}.stderr"
        )

        rpms = builder.root.exposed_retrieve_rpm_lists()
        _log.debug(f"{self.host.ljust(20)} RPMs built: {' '.join(rpms)}")

        for rpm in rpms:
            _log.info(f"{self.host.ljust(20)} Retrieving file {rpm}")
            with open(os.path.basename(rpm), "wb") as stream:
                stream.write(builder.root.exposed_retrieve_file(rpm))

        _log.info(f"{self.host.ljust(20)} Stopping the builder container")
        returncode, outs, errs = self.conn.root.stop_builder(container_id)
        if returncode == 0:
            _log.info(f"{self.host.ljust(20)}    Container stopped sucessfully")
        else:
            _log.info(f"{self.host.ljust(20)}    Failed to stop container")
            print(errs)
            return returncode

    def do_clean_images(self):
        """Clean remote_builders related images.

        :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
        :arg args: the argparse object returned by ``parse_arguments()``.

        """
        _log.debug(f"{host.ljust(20)} image:       %s", args.image)
        _log.debug(f"{host.ljust(20)} dry_run:     %s", args.dry_run)

        returncode, outs, errs, images = conn.root.list_images()
        if returncode == 0:
            _log.info(f"{host.ljust(20)}    List of container retrieved sucessfully")
        else:
            _log.info(f"{host.ljust(20)}    Failed to retrieve the list of containers")
            print(errs)
            return returncode

        if not images:
            _log.info(f"{host.ljust(20)} No relevant images retrieved on the host {host}")
            return 0

        if args.dry_run:
            if args.image:
                if args.image in images:
                    _log.info(f"{host.ljust(20)} Would delete image {args.image}")
                else:
                    _log.info(
                        f"{host.ljust(20)} Container {args.image} not found on the server."
                    )
            else:
                _log.info(f"{host.ljust(20)} Would delete image(s): {' '.join(images)}")
        else:
            if args.image:
                if args.image in images:
                    outcodes = conn.root.clean_images([args.image])
                else:
                    _log.info(
                        f"{host.ljust(20)} Container {args.image} not found on the server."
                    )
            else:
                outcodes = conn.root.clean_images(images)

            if set(outcodes) != set([0]):
                _log.info(
                    f"{host.ljust(20)} Failed to clean all the container images on the server."
                )
            else:
                _log.info(
                    f"{host.ljust(20)} Successfully cleaned all the container images on the server."
                )


def process_host(arg_list):
    """Process the host based on the arguments provided to the CLI."""
    config, host, args = arg_list
    return_code = 0
    remote_builder = RemoteBuilder(config, host, args)
    remote_builder.conn = remote_builder._connect(start_server=True)
    # Act based on the arguments given
    try:
        print(args.func)
        method = getattr(remote_builder, args.func)
        method()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        return_code = 1
    except exceptions.BaseRemoteBuilderError as err:
        print(err)
        return_code = 3
    except Exception as err:
        print("Error: {0}".format(err))
        logging.exception("Generic error catched:")
        return_code = 2
    finally:
        if remote_builder.proc:
            print("Stopping server process")
            remote_builder.proc.kill()

    # if return_code != 0:
    return return_code


def main():
    """Start of the application."""

    # Parse the arguments
    args = parse_arguments(sys.argv[1:])

    logging.basicConfig(
        format="%(asctime)-10s %(levelname)-6s %(message)s",
        datefmt="%H:%M:%S",
    )
    _log.setLevel(logging.INFO)
    if args.debug:
        _log.setLevel(logging.DEBUG)

    try:
        config = get_config(args.config)
    except configparser.Error as error:
        print(f"ERROR: {error}")
        return 5

    if args.sequential:
        return_code = 0
        for _, host in config.items("hosts"):
            rtn_code = process_host([config, host, args])
            if rtn_code != 0:
                # Any return code that indicates a failure is good enough
                return_code = rtn_code
    else:
        p = Pool(5)
        hosts = [it[1] for it in config.items("hosts")]
        return_code = p.map(process_host, itertools.product([config], hosts, [args]))
        return_code = 1 if any(return_code) else 0

    return return_code


if __name__ == "__main__":
    sys.exit(main())
