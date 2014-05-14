#!/bin/bash
set -ev

git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.5.0
./autogen.sh
./configure
make && sudo make install
if [[ $TRAVIS_OS_UNAME = 'Linux' ]]; then sudo ldconfig; fi
