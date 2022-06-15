import argparse
import configparser
import itertools
import json
import logging
from multiprocessing import cpu_count, Pool
import os
import subprocess
import sys
import tempfile
import time

import rpyc

from remote_builder.server import exceptions


_log = logging.getLogger(__name__)

description = """Runs a command remotely.
This program takes the same configuration file as remote_builder and will run
the command on the different hosts sequentially.
For remote host, the specified working directory will be mounted via sshfs.
"""


def parse_arguments(args=None):
    """Set-up the argument parsing."""
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description,
    )

    parser.add_argument(
        "config",
        help="Configuration file to use",
    )

    parser.add_argument(
        "working_directory",
        help="Working directory to be made accessible",
    )

    parser.add_argument(
        "command",
        help="Command to run in the specified working directory",
    )

    parser.add_argument(
        "--debug",
        default=False,
        action="store_true",
        help="Increase the verbosity of the information displayed",
    )

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
    _log.info(f"Connecting to {host} using {connection_type} with timeout: {timeout}")
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


def process_host(arg_list):
    """Process the host based on the arguments provided to the CLI."""
    config, host, args = arg_list
    connection_type = config.get(host, "type")
    return_code = 0
    working_directory = None
    rem = _establish_connection(config, host, with_sources=False)
    rem2 = _establish_connection(config, host, with_sources=False)
    # Act based on the arguments given
    try:
        if connection_type == "ssh":
            out = rem["ls"]().split()

            create_key = True
            ssh_keys = []
            with open(
                os.path.join(os.path.expanduser("~"), ".ssh", "authorized_keys")
            ) as stream:
                ssh_keys = [r.strip() for r in stream.readlines()]
            # print(ssh_keys)

            # Delete the accelerator key if it's in there
            if "accelerator" in out or "accelerator.pub" in out:
                # Retrieve that ssh key
                _log.info("Reading the ssh key for the accelerator")
                returncode, outs, errs = rem["cat"].run(["accelerator.pub"])
                if returncode != 0:
                    raise Exception("Failed to retrieve the accelerator's ssh key")
                outs = outs.strip()

                if outs not in ssh_keys:
                    _log.info(
                        "Deleting existing key since they are not known on the client"
                    )
                    rem["rm"].run(["accelerator", "accelerator.pub"])
                else:
                    create_key = False
                    _log.debug("The accelerator's key is already set-up")

            if create_key:
                # Create a ssh key
                _log.debug("Creating ssh key for the accelerator")
                keygen = rem["/usr/bin/ssh-keygen"]
                returncode, outs, errs = keygen.run(
                    ["-f", "accelerator", "-t", "ecdsa", "-b", "521"]
                )
                if returncode != 0:
                    raise Exception("Failed to create the accelerator's ssh key")

                # Retrieve that ssh key
                _log.debug("Retrieving the ssh key for the accelerator")
                returncode, outs, errs = rem["cat"].run(["accelerator.pub"])
                if returncode != 0:
                    raise Exception("Failed to retrieve the accelerator's ssh key")
                outs = outs.strip()

                # Insert it in the list
                ssh_keys.append("# Keys added by accelerator")
                ssh_keys.append(outs)
                ssh_keys.append("# End of keys added by accelerator")

                # Re-write the authorized_keys file
                _log.info("Inserting accelerator's key into ~/.ssh/authorized_keys")
                with open(
                    os.path.join(os.path.expanduser("~"), ".ssh", "authorized_keys"),
                    "w",
                ) as stream:
                    stream.write("\n".join(ssh_keys))

        local_home = os.path.expanduser("~")
        remote_home = rem.env["HOME"]
        working_directory = args.working_directory.replace(local_home, remote_home)

        if connection_type == "ssh":
            # sshfs mount the target folder
            rem["mkdir"].run(["-p", working_directory])
            _log.debug("Starting sshfs")
            p = rem2["sshfs"].run(
                [
                    f"pierrey@192.168.1.90:{args.working_directory}",
                    working_directory,
                    "-o",
                    f"IdentityFile=/{remote_home}/accelerator",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "allow_other,default_permissions",
                ]
            )

        _log.info("Running your command:")
        if connection_type == "ssh":
            proc = rem.popen(
                [args.command],
                cwd=working_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            proc = subprocess.Popen(
                [args.command],
                cwd=working_directory,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True,
            )

        while True:
            if proc.stdout:
                output = proc.stdout.readline().decode("utf8")
            if proc.poll() is not None and output == "":
                break
            if output:
                print(output.strip())
        retval = proc.poll()

        proc.wait()
        outs, errs = proc.communicate()

        _log.debug("Exit code: %s", proc.returncode)
        _log.debug("Standard error:\n%s", errs.decode("utf-8"))
        _log.info("... Done")

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
        if working_directory and connection_type == "ssh":
            rem2["umount"].run([working_directory])

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

    return_code = 0
    for _, host in config.items("hosts"):
        rtn_code = process_host([config, host, args])
        if rtn_code != 0:
            # Any return code that indicates a failure is good enough
            return_code = rtn_code

    return return_code


if __name__ == "__main__":
    sys.exit(main())
