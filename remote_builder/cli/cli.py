import argparse
import logging
import os
import sys

import rpyc

from remote_builder.server import exceptions


_log = logging.getLogger(__name__)


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

    # refresh-gitolite
    _parser_rpmbuild(subparser)

    return parser.parse_args(args)


def do_rpmbuild(conn, args):
    """Build remotly the specified source rpm


    :arg conn: rpyc.core.protocol.Connection object connecting the client to the remote server.
    :arg args: the argparse object returned by ``parse_arguments()``.

    """
    _log.debug("source_rpm:     %s", args.source_rpm)

    if not os.path.exists(args.source_rpm):
        raise OSError("File not found: %s", args.source_rpm)

    conn.root.create_workdir()
    srpm_filename = os.path.basename(args.source_rpm)

    _log.info(f"Sending the source rpm:   {args.source_rpm}")
    with open(args.source_rpm, "rb") as stream:
        conn.root.write_srpm(srpm_filename, stream.read())

    _log.info(f"Building the source rpm:  {args.source_rpm}")
    outs, errs, returncode = conn.root.build_srpm(srpm_filename)
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

    rpms = conn.root.exposed_retrieve_rpm_lists()
    _log.info(f"RPMs built: {' '.join(rpms)}")

    for rpm in rpms:
        _log.info(f"Retrieving file {rpm}")
        with open(os.path.basename(rpm), "wb") as stream:
            stream.write(conn.root.exposed_retrieve_file(rpm))


def main():
    """Start of the application."""

    # Parse the arguments
    args = parse_arguments(sys.argv[1:])

    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s")
    _log.setLevel(logging.INFO)
    if args.debug:
        _log.setLevel(logging.DEBUG)

    _log.debug(f"Connecting to {args.host}:{args.port}")
    conn = rpyc.connect(
        host=args.host,
        port=args.port,
        config={
            "sync_request_timeout": 69 * 60 * 3, # 3h timeout
        },
    )

    # Act based on the arguments given
    return_code = 0
    try:
        args.func(conn, args)
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


if __name__ == "__main__":
    sys.exit(main())
