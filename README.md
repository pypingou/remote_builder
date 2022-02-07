Remote Builder
==============

Remote builder is a simple RPC based application that can be used to build RPMs
on a configured set of hosts. You can therefore use this project to easily build
a RPM onto hosts of different architectures (e.g: x86_64 and arm64).

To do this, a CLI tool connects to a remote builder server. The server creates
a podman container running the same remote builder server code. The CLI can
then connect to the server code running inside the container. The source RPM
is then rebuilt into RPMs which can be exported back into the host running the
CLI.

This allows to use container as buildroot for building RPMs on a remote (or
local) server.

More information about the project can be found in the `docs` folder which also
contains a `mkdocs` project. If you have `mkdocs` install you can browse locally
the documentation using `mkdocs --serve`.
