Installing and running remote builder
=====================================

Installing remote builder
-------------------------

You can install remote builder in a few ways:

### From pip

You can very simply install remote builder from pip using:
```
pip install remote_builder
```

You can also install the latest (potentially in development) version of the code
using:
```
pip install rpyc git+https://github.com/pypingou/remote_builder.git
```

### From git

This allows to run the latest (potentially in development version of the code)
but it can also allow to run the code without installing it per say.

You can simply do so by doing:
```
git clone https://github.com/pypingou/remote_builder
```

If you choose to this method you will have to prefix all the command listed
below for running the server or the CLI with `PYTHONPATH=.`.

Running remote builder
----------------------

### Running the server

The client will use podman to create and start a builder container on the server.
That container will run the remote-builder server that the client will connect
to to rebuild the SRPM and build the RPM.

- **Dependencies**

Here is the list of dependencies for the server:

- podman

### Running the CLI

To run the CLI you can simply run either:

- the `remote_builder` CLI, if you choose to install remote builder from pip.
or
- `PYTHONPATH=. python remote_builder/cli/cli.py` if you choose to run
  remote builder from git. Run that command from the top level of the git
  repository.

In both cases, you can use `--help` for more information about the different
options and arguments available.

- **Dependencies**

Here is the list of dependencies for the CLI:

- RPyC (python3-rpyc on Fedora)
- sshpass (optional): used when connecting to a remote host using a ssh key
