#!/bin/bash
set -ev

git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.5.0
./autogen.sh
if [[ $TRAVIS_OS_UNAME = 'Linux' ]]; then ./configure; fi
if [[ $TRAVIS_OS_UNAME = 'Darwin' ]]; then ./configure LDFLAGS="-arch i386"; fi
make && sudo make install
if [[ $TRAVIS_OS_UNAME = 'Linux' ]]; then sudo ldconfig; fi
