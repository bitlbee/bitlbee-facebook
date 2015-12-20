#!/bin/bash
set -e

git clone https://github.com/bitlbee/bitlbee /tmp/bitlbee
cd /tmp/bitlbee

./configure \
    --events=glib \
    --ssl=gnutls \
    --doc=0 \
    --jabber=0 \
    --msn=0 \
    --oscar=0 \
    --twitter=0 \
    --yahoo=0

make
sudo make install install-dev
