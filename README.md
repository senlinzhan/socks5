![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
# Socks5
A C++11 socks5 proxy server based on Libevent

## Feature
The Socks5 server has the following features:
- Support for "No Auth" authentication 
- Support for "Username/Password" authentication
- Support for the CONNECT command
- Support both IPv4 and IPv6
- Support aes-256-cbc encryption algorithm 
## Build
Build from source on Ubuntu 16.04:
```bash
# Install packages
$ sudo apt-get update && sudo apt-get install build-essential libssl-dev cmake -y

# Install Libevent
$ wget https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz
$ tar -xzvf libevent-2.1.8-stable.tar.gz
$ cd libevent-2.1.8-stable
$ ./configure
$ make
$ sudo make install
$ sudo ldconfig -v
$ cd ..
$ rm -r libevent-2.1.8-stable

# Build from source
$ git clone https://github.com/senlinzhan/socks5.git
$ cd socks5
$ git submodule update --init
$ mkdir build && cd build
$ cmake ..
$ make
```
## Usage

## TODO
Features that will be added in the future:
- Support for the BIND command
- Support for the ASSOCIATE command
- Support other encryption algorithms
