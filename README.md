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
$ rm -r libevent-2.1.8-stable* 

# Build from source
$ git clone https://github.com/senlinzhan/socks5.git
$ cd socks5
$ git submodule update --init
$ mkdir build && cd build
$ cmake ..
$ make

# Run all unit testing
$ make test
```
## Usage
Run local server to accept all client connections:
```bash
$ ./bin/local \
    -host="0.0.0.0" \                        # local server hostname
    -port=5050 \                             # local server port
    -remoteHost="127.0.0.1" \                # proxy server hostname
    -remotePort=6060 \                       # proxy server port
    -key=12345678123456781234567812345678    # 32 bytes secret key
    -logtostderr                             # log messages to stderr 
```
Run proxy server to accept connections from the local server:
```bash
$ ./bin/socks5 \
    -host="0.0.0.0" \                        # proxy server hostname
    -port=5050 \                             # proxy server port
    -key=12345678123456781234567812345678    # 32 bytes secret key
    -username="admin"                        # username <optional>
    -password="admin"                        # password <optional>	
    -logtostderr                             # log messages to stderr 
```
## TODO
Features that will be added in the future:
- Support for the BIND command
- Support for the ASSOCIATE command
- Support other encryption algorithms
