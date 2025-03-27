# Script install pip3 and rust

# SAFECYBER 4.0

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3.8 get-pip.py

curl https://sh.rustup.rs -sSf -o rustup-init.sh
sh rustup-init.sh

SafeCyber ou BLuepexUTM
vi /etc/csh.cshrc
set path = ($HOME/.cargo/bin $path)
source ~/.cshrc

OpnSense
vi ~/.cshrc
set path = ($HOME/.cargo/bin $path)

para GO lang
setenv PATH "${PATH}:/usr/local/go/bin"

fetch https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz
pkg install -y gcc gmake autoconf automake libtool pkgconf
pkg install -y libffi libffi-dev readline readline-dev
tar -xzf Python-3.11.9.tgz
cd Python-3.11.9/

./configure --enable-optimizations --enable-shared --with-ensurepip=install
make
make install

python3.11 -m ensurepip --upgrade
pip3 install cython

# SAFECYBER 3.0

fetch https://www.python.org/ftp/python/3.11.9/Python-3.11.9.tgz
tar -xzf Python-3.11.9.tgz
cd Python-3.11.9
./configure --enable-optimizations --enable-shared --with-ensurepip=install
make
make install

setenv LD_LIBRARY_PATH /usr/local/libope
source ~/.cshrc

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py

Baixar o ports do FREEBSD 10
fetch http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/11.1-RELEASE/ports.txz
tar -xzf ports.txz -C /usr
cd /usr/usr
mv ports ../
rm -rf usr/
cd ..

