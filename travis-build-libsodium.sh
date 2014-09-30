#!/bin/bash
set -ev

git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/1.0.0
./autogen.sh
if [[ $TRAVIS_OS_UNAME = 'Darwin' ]]; then 
  export CFLAGS="-Os -m32 -arch i386";
  export LDFLAGS="-m32 -arch i386";
fi
./configure
make && sudo make install
if [[ $TRAVIS_OS_UNAME = 'Linux' ]]; then sudo ldconfig; fi
