Configuration file
==================

When running remote builder's CLI you can use a configuration file to specify
to which host the CLI should connect to.

Here is an example configuration file:
```
[hosts]
host1 = localhost
host2 = 192.168.1.64

[localhost]
type=       socket
port=       18861
timeout=    14400

[192.168.1.64]
type=       ssh
ssh_port=   22
port=       18861
timeout=    14400
user=       guest
password=   password
```

Here are some explanations:

## The hosts section

The `hosts` section contains a list of hosts the CLI will connect to. The
options' names (`host1`, `host2`...) do not matter, but the options's values
must be the name (hostname or IP address) of the host to connect to.

**This section must be specified.**

## The types

Each host section, must contain a `type` option. That `type` can be either of
value `socket` or `ssh`.

A `socket` type means the CLI can connect to the server directly at the specified
port. This is likely be the simplest approach when the server is running localy
(ie: `localhost`, or `127.0.0.1`...). It can also be used if you do port forwarding
from a remote system locally (for example using a ssh tunnel).

A `ssh` type means the CLI can connect to a server running remotely via ssh.
The way this is done is by creating a ssh tunnel using the [plumbum](https://plumbum.readthedocs.io/en/latest/)
library (used withing [RPyc](https://rpyc.readthedocs.io/en/latest/)).

**This option must be specified.**

## The port

The `port` option must be an integer specifying the port at which the server is
listening. It can be either the local port or the port of the server running
locally on the remote host.

**This option must be specified.**

## The timeout

The `timeout` option can be used to specify the timeout value (in seconds) after
which the connection to the server will abort if no results have been sent back
to the CLI.

This default to `60 * 60 * 3` ie: 3 hours.

## The SSH options

If you want to connect to a remote host running the server, you can do so using
a ssh tunnel via the `ssh` type.

There are a few options available for this connection type:

* `ssh_port` simply the port at which the ssh server is listening, defaults to `22`.
* `user` the user to connect to the remote server as
* `password` this option can be either the password of the user listed just above
  or, if you connect to the remote server using an ssh key, it can be the password
  of that ssh key.
* `keyfile` the path to the ssh key to use to connect to the remote server

**Either a `user` or a `keyfile` must be specified for host of type `ssh`.**


## Default configuration file

Here is the default configuration file of remote builder:
```
[hosts]
host1 = localhost

[localhost]
type=       socket
port=       18861
```

It allows to run the CLI against a server running locally (at the default port).
