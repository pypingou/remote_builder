import argparse
import configparser
import itertools
import json
import logging
from multiprocessing import cpu_count, Pool
import os
import sys
import tempfile

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


def _establish_connection(config, host, with_sources=True):
    connection_type = config.get(host, "type")
    timeout = config.getint(host, "timeout", fallback=(60 * 60 * 3))  # 3h timeout
    _log.info(
        f"Starting builder containers on {host} using {connection_type} with timeout: {timeout}"
    )
    import plumbum

    if connection_type == "socket":
        rem = plumbum.local
    else:
        user = config.get(host, "user", fallback=None)
        keyfile = config.get(host, "keyfile", fallback=None)
        password = config.get(host, "password", fallback=None)
        ssh_port = config.getint(host, "ssh_port", fallback=22)
        _log.debug(
            f"Connecting via ssh as {user} using the keyfile {keyfile} and "
            f"or password: {'***' if password else password}"
        )

        # FYI here are is the doc about this object:
        # https://plumbum.readthedocs.io/en/latest/api/machines.html#plumbum.machines.ssh_machine.SshMachine

        rem = plumbum.SshMachine(
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

    return rem


def _start_server(config, host, builder_port=18862, with_sources=True):
    """Connect to the host specified in the configuration file using its information.

    In this method we allow to override the 'port' used by the server service.
    """

    rem = _establish_connection(config, host, with_sources=with_sources)

    containerfile = config.get("container", "containerfile", fallback=None)
    containerimage = config.get("container", "containerimage", fallback=None)

    if containerfile:
        with tempfile.TemporaryDirectory(prefix="remote_builder-") as tempdirname:
            containerfilename = os.path.join(tempdirname.name, "Containerfile_builder")
            _log.info(
                f"Writing down the Dockerfile for builders at {containerfilename}"
            )
            with open(containerfilename, "wb") as out_file:
                out_file.write(containerfile.encode("utf-8"))

            _log.info("Building builder container")
            cmd = [
                "build",
                "-f",
                containerfilename,
                "--rm",
                "-t",
                "rs_builder",
            ]
    elif containerimage:
        # Use the specified container image
        _log.info(f"Pulling the builder container: {containerimage}")
        cmd = ["pull", containerimage]

    returncode, outs, errs = rem["podman"].run(cmd)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Container created sucessfully")
    else:
        raise exceptions.BaseRemoteBuilderError(
            f"{host.ljust(20)}   Failed to create container"
        )

    image_id = outs.strip().split("\n")[-1]
    _log.info(f"Container image built: {image_id}")

    _log.info(f"{host.ljust(20)} Starting the builder container")
    cmd = ["run", "-d", "-p", f"{builder_port}:18861/tcp", "--rm", image_id]
    returncode, outs, errs = rem["podman"].run(cmd)
    container_id = outs.strip()

    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Container started sucessfully")
    else:
        print(errs)
        raise exceptions.BaseRemoteBuilderError(
            f"{host.ljust(20)}   Failed to start container"
        )

    return (rem, container_id)


def _connect(config, host, port=None):
    """Connect to the host specified in the configuration file using its information.

    In this method we allow to override the 'port' used by the server service.
    """
    port = port or config.get(host, "port")
    connection_type = config.get(host, "type")
    timeout = config.getint(host, "timeout", fallback=(60 * 60 * 3))  # 3h timeout
    _log.info(
        f"Connecting to {host}:{port} using {connection_type} with timeout: {timeout}"
    )

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
        rem = _establish_connection(config, host)
        conn = rpyc.ssh_connect(
            remote_machine=rem,
            remote_port=port,
            config={
                "sync_request_timeout": timeout,
            },
        )

    return conn


def do_rpmbuild(config, host, args):
    """Build remotly the specified source rpm


    :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
    :arg args: the argparse object returned by ``parse_arguments()``.

    """
    _log.debug(f"{host.ljust(20)} source_rpm:     %s", args.source_rpm)

    if not os.path.exists(args.source_rpm):
        raise OSError("File not found: %s", args.source_rpm)

    new_port = int(config.get(host, "port")) + 1
    rem, container_id = _start_server(config, host, new_port)

    builder = _connect(config, host, new_port)
    builder.root.create_workdir()

    srpm_filename = os.path.basename(args.source_rpm)

    _log.info(
        f"{host.ljust(20)} Uploading the source rpm:            {args.source_rpm}"
    )
    with open(args.source_rpm, "rb") as stream:
        builder.root.write_srpm(srpm_filename, stream.read())

    _log.info(
        f"{host.ljust(20)} Installing the source rpm:           {args.source_rpm}"
    )
    returncode, outs, errs = builder.root.install_srpm(srpm_filename)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Installed SRPM sucessfully")
    else:
        _log.info(f"{host.ljust(20)}    Failed to install the SRPM")
        print(outs)
        print(errs)
        return returncode

    _log.info(
        f"{host.ljust(20)} Rebuilding the source rpm:           {args.source_rpm}"
    )
    returncode, outs, errs, source_rpm = builder.root.build_srpm()
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Rebuilt SRPM sucessfully")
    else:
        _log.info(f"{host.ljust(20)}    Failed to rebuild the SRPM")
        print(outs)
        print(errs)
        return returncode

    _log.info(f"{host.ljust(20)} Installing build dependencies of:    {source_rpm}")
    returncode, outs, errs = builder.root.install_build_dependencies(source_rpm)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Dependencies installed sucessfully")
    else:
        _log.info(f"{host.ljust(20)}    Failed to install dependencies")
        print(outs)
        print(errs)
        return returncode

    _log.info(f"{host.ljust(20)} Building the RPM from:               {source_rpm}")
    returncode, outs, errs = builder.root.build_rpm(source_rpm)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    RPM built sucessfully")
    else:
        _log.info(f"{host.ljust(20)}    Failed to build the RPMs")
    _log.debug(f"{host.ljust(20)} Return code: {returncode}")
    with open(f"{srpm_filename}.{host}.stdout", "w") as stream:
        stream.write(outs)
    with open(f"{srpm_filename}.{host}.stderr", "w") as stream:
        stream.write(errs)
    _log.info(
        f"{host.ljust(20)}    stdout log written in: {srpm_filename}.{host}.stdout"
    )
    _log.info(
        f"{host.ljust(20)}    stderr log written in: {srpm_filename}.{host}.stderr"
    )

    rpms = builder.root.exposed_retrieve_rpm_lists()
    _log.debug(f"{host.ljust(20)} RPMs built: {' '.join(rpms)}")

    for rpm in rpms:
        _log.info(f"{host.ljust(20)} Retrieving file {rpm}")
        with open(os.path.basename(rpm), "wb") as stream:
            stream.write(builder.root.exposed_retrieve_file(rpm))

    _log.info(f"{host.ljust(20)} Stopping the builder container")
    cmd = ["stop", container_id]
    returncode, outs, errs = rem["podman"].run(cmd)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    Container stopped sucessfully")
    else:
        _log.info(f"{host.ljust(20)}    Failed to stop container")
        print(errs)
        return returncode


def do_clean_images(config, host, args):
    """Clean remote_builders related images.

    :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
    :arg args: the argparse object returned by ``parse_arguments()``.

    """
    _log.debug(f"{host.ljust(20)} image:       %s", args.image)
    _log.debug(f"{host.ljust(20)} dry_run:     %s", args.dry_run)

    rem = _establish_connection(config, host, with_sources=False)

    cmd = ["images", "--format", "json"]
    returncode, outs, errs = rem["podman"].run(cmd)
    if returncode == 0:
        _log.info(f"{host.ljust(20)}    List of container retrieved sucessfully")
    else:
        print(errs)
        raise exceptions.BaseRemoteBuilderError(
            f"{host.ljust(20)}    Failed to retrieve the list of containers"
        )

    images = []
    if returncode == 0:
        data = json.loads(outs)
        for image in data:
            for name in image.get("Names", []):
                if "rs_builder" in name:
                    images.append(image.get("Id"))
                    break
    _log.debug(f"Images Id retrieved: {' '.join(images)}")

    if not images:
        _log.info(f"{host.ljust(20)} No relevant images retrieved on the host {host}")
        return 0

    def _clean_images(images):
        """Delete the images specified in the provided list."""
        _log.info(f"Deleting the podman images: {' '.join(images)}")
        outcodes = []
        for image in images:
            cmd = ["podman", "rmi", image, "-f"]
            returncode, _, _ = rem["podman"].run(cmd)
            outcodes.append(returncode)
            _log.debug(
                f"Deleting podman images {image} finished with the code: {returncode}"
            )

        return outcodes

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
                outcodes = _clean_images([args.image])
            else:
                _log.info(
                    f"{host.ljust(20)} Container {args.image} not found on the server."
                )
        else:
            outcodes = _clean_images(images)

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
    # Act based on the arguments given
    try:
        return_code = args.func(config, host, args)
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
        hosts = [it[1] for it in config.items("hosts")]
        pool_size = len(hosts) + 1
        if pool_size > cpu_count():
            pool_size = cpu_count() + 1
        p = Pool(pool_size)
        return_code = p.map(process_host, itertools.product([config], hosts, [args]))
        return_code = 1 if any(return_code) else 0

    return return_code


if __name__ == "__main__":
    sys.exit(main())
