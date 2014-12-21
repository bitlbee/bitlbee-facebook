#!/bin/sh

test -z "$srcdir" && srcdir=$(dirname "$0")
test -z "$srcdir" && srcdir=.

cwd=$(pwd)
cd "$srcdir"

autoreconf --verbose --force --install || exit $?

cd "$cwd"
"$srcdir/configure" $@
