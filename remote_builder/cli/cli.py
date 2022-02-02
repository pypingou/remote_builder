import argparse
import configparser
import logging
import os
import sys

import rpyc

from remote_builder.server import exceptions


_log = logging.getLogger(__name__)


_default_config = """
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
    local_parser.set_defaults(func=do_rpmbuild)


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
    local_parser.set_defaults(func=do_clean_images)


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
        "--config",
        help="Configuration file to use",
    )

    parser.add_argument(
        "--host",
        default="localhost",
        help="Host of the run the server at (detaulf to localhost)",
    )

    parser.add_argument(
        "-p", "--port",
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
        raise BaseRemoteBuilderError("Configuration file has no 'hosts' section")

    for _, host in config.items("hosts"):
        if not "type" in config.options(host):
            raise BaseRemoteBuilderError(f"Host {host} has not 'type' option")
        if config.get(host, "type") not in ["ssh", "socket"]:
            raise BaseRemoteBuilderError(f"Host {host}'s type option is invalid, not either: ssh, socket")
        if not config.get(host, "port"):
            raise BaseRemoteBuilderError(f"Host {host} has no port specified")
        if config.get(host, "type") == "ssh":
            if not config.get(host, "user") and not config.get(host, "keyfile"):
                raise BaseRemoteBuilderError(f"Host {host} has no user or keyfile specified")


def get_config(configfile=None):
    """Returns the ConfigParser object with the loaded configuration."""
    _log.debug("Loading the default configuration")
    config = configparser.ConfigParser()
    config.read_string(_default_config)

    if configfile:
        _log.debug(f"Updating the configuration file from {configfile}")
        config.read(configfile)

    _validate_config(config)
    return config


def _connect(config, host, port=None):
    """Connect to the host specified in the configuration file using its information.

    In this method we allow to override the 'port' used by the server service.
    """
    port = port or config.get(host, "port")
    connection_type = config.get(host, "type")
    timeout = config.getint(host, "timeout", fallback=(60 * 60 * 3)) # 3h timeout
    _log.info(f"Connecting to {host}:{port} using {connection_type} with timeout: {timeout}")

    if connection_type == "socket":
        conn = rpyc.connect(
            host=host,
            port=port,
            config={
                "sync_request_timeout": timeout,
            },
            keepalive=True,
        )
    else:
        user=config.get(host, "user", fallback=None)
        keyfile=config.get(host, "keyfile", fallback=None)
        password=config.get(host, "password", fallback=None)
        ssh_port=config.getint(host, "ssh_port", fallback=22)
        _log.debug(f"Connecting via ssh as {user} using the keyfile {keyfile} and or password: {'***' if password else password}")
        from plumbum import SshMachine
        rem = SshMachine(
            host,
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
            remote_port=port,
            config={
                "sync_request_timeout": timeout,
            },
        )

    return conn


def do_rpmbuild(config, host, conn, args):
    """Build remotly the specified source rpm


    :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
    :arg args: the argparse object returned by ``parse_arguments()``.

    """
    _log.debug("source_rpm:     %s", args.source_rpm)

    if not os.path.exists(args.source_rpm):
        raise OSError("File not found: %s", args.source_rpm)

    conn.root.create_workdir()

    _log.info("Creating the builder container")
    returncode, image_id, new_port = conn.root.create_builder(args.port)
    if returncode == 0:
        _log.info("  Container created sucessfully")
    else:
        _log.info("  Failed to create container")
        return returncode

    builder = _connect(config, host, new_port)
    builder.root.create_workdir()

    srpm_filename = os.path.basename(args.source_rpm)

    _log.info(f"Sending the source rpm:   {args.source_rpm}")
    with open(args.source_rpm, "rb") as stream:
        builder.root.write_srpm(srpm_filename, stream.read())

    _log.info(f"Installing build dependencies of:  {args.source_rpm}")
    outs, errs, returncode = builder.root.install_build_dependencies(srpm_filename)
    if returncode == 0:
        _log.info("  Dependencies installed sucessfully")
    else:
        _log.info("  Failed to install dependencies")
        return returncode

    _log.info(f"Building the source rpm:  {args.source_rpm}")
    outs, errs, returncode = builder.root.build_srpm(srpm_filename)
    if returncode == 0:
        _log.info("  RPM built sucessfully")
    else:
        _log.info("  Failed to build the RPMs")
    _log.debug(f"Return code: {returncode}")
    with open(f"{srpm_filename}.stdout", "w") as stream:
        stream.write(outs.decode("utf-8"))
    with open(f"{srpm_filename}.stderr", "w") as stream:
        stream.write(errs.decode("utf-8"))
    _log.info(f"  stdout log written in: {srpm_filename}.stdout")
    _log.info(f"  stderr log written in: {srpm_filename}.stderr")

    rpms = builder.root.exposed_retrieve_rpm_lists()
    _log.info(f"RPMs built: {' '.join(rpms)}")

    for rpm in rpms:
        _log.info(f"Retrieving file {rpm}")
        with open(os.path.basename(rpm), "wb") as stream:
            stream.write(builder.root.exposed_retrieve_file(rpm))


def do_clean_images(config, host, conn, args):
    """Clean remote_builders related images.

    :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
    :arg args: the argparse object returned by ``parse_arguments()``.

    """
    _log.debug("image:       %s", args.image)
    _log.debug("dry_run:     %s", args.dry_run)

    images, stderr, returncode = conn.root.list_images()
    if returncode == 0:
        _log.info("  Container created sucessfully")
    else:
        _log.info("  Failed to create container")
        print(stderr)
        return returncode

    if args.dry_run:
        if args.image:
            if args.image in images:
                _log.info(f"Would delete image {args.image}")
            else:
                _log.info(f"Container {args.image} not found on the server.")
        else:
            _log.info(f"Would delete image(s): {' '.join(images)}")
    else:
        if args.image:
            if args.image in images:
                outcodes = conn.root.clean_images([args.image])
            else:
                _log.info(f"Container {args.image} not found on the server.")
        else:
            outcodes = conn.root.clean_images(images)

        if set(outcodes) != set([0]):
            _log.info("Failed to clean all the container images on the server.")
        else:
            _log.info("Successfully cleaned all the container images on the server.")


def main():
    """Start of the application."""

    # Parse the arguments
    args = parse_arguments(sys.argv[1:])

    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    _log.setLevel(logging.INFO)
    if args.debug:
        _log.setLevel(logging.DEBUG)

    try:
        config = get_config(args.config)
    except BaseRemoteBuilderError as error:
        print(f"ERROR: {error}")
        return 5

    return_code = 0
    for _, host in config.items("hosts"):
        conn = _connect(config, host)

        # Act based on the arguments given
        try:
            args.func(config, host, conn, args)
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

        if return_code != 0:
            return return_code

    return return_code


if __name__ == "__main__":
    sys.exit(main())
