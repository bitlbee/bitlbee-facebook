The Facebook protocol plugin for bitlbee. This plugin uses the Facebook
Messenger MQTT-based protocol.

This project is not affiliated with Facebook, Inc.

## Usage

General usage instructions are available in the bitlbee wiki:

https://wiki.bitlbee.org/HowtoFacebookMQTT

## Installing with packages

### Debian/ubuntu APT repo

An APT repo for several recent debian/ubuntu versions is available here:

https://jgeboski.github.io/

This builds git/development versions.

### Debian buster/backports

Debian's official repos have packages for releases of this plugin, with the
slightly different name "bitlbee-plugin-facebook". Use the APT repo if it's not
the latest.

    $ apt install bitlbee-plugin-facebook

### Fedora

    $ dnf install bitlbee-facebook

### RHEL/CentOS

Follow the general instructions for enabling EPEL before installing it:

http://fedoraproject.org/wiki/EPEL#How_can_I_use_these_extra_packages.3F

    $ yum install bitlbee-facebook

## Building from source

The following packages are required: autoconf, automake, libtool, glib2,
json-glib, bitlbee (names may vary across distros)

Example for debian-based systems:

    apt install build-essential autoconf automake libtool libglib2.0-dev libjson-glib-dev bitlbee-dev

Example for Fedora-based systems:

    dnf install gcc autoconf automake libtool glib2-devel json-glib-devel bitlbee-devel

Make sure bitlbee and its headers have been installed. If bitlbee came
from the distribution's repository, it will most likely need the
development package, like bitlbee-dev or bitlbee-devel in the example
above.

If bitlbee was built by hand (or alike via a script), ensure the make
target `install-dev` is invoked. This target is not called by default,
and will install the headers that are needed.

    $ git clone https://github.com/bitlbee/bitlbee-facebook.git
    $ cd bitlbee-facebook

With a "global" (or system) bitlbee installation:

    $ ./autogen.sh
    $ make
    $ make install

Otherwise, before running those commands, set PKG_CONFIG_PATH to the path to
the `bitlbee.pc` file. For example:

    $ export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig/

## Debugging

One of the two supported environment variables can be defined to enable
debugging output. This can be used in unison with debuggers such as
GDB, which should enable easier tracing of bugs.

When posting to the issue tracker, please ensure any sensitive
information has been stripped.

For bitlbee and the plugin:

    $ export BITLBEE_DEBUG=1
    OR
    $ BITLBEE_DEBUG=1 gdb ...

For just the plugin:

    $ export BITLBEE_DEBUG_FACEBOOK=1
    OR
    $ BITLBEE_DEBUG_FACEBOOK=1 gdb ...

Obtaining a GDB backtrace:

    $ gdb \
        -ex 'handle SIGPIPE nostop noprint pass' \
        -ex 'break g_log' -ex run -ex bt \
        --args /usr/sbin/bitlbee -Dnvc /etc/bitlbee/bitlbee.conf
