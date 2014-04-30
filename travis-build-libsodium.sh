git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout tags/0.4.5
./autogen.sh
./configure
make && sudo make install
