# Socks5
A C++11 socks5 proxy server based on Libevent

## Feature
The Socks5 server has the following features:
- Support for "No Auth" authentication 
- Support for "Username/Password" authentication
- Support for the CONNECT command
- Support both IPv4 and IPv6
- Support aes-256-cbc encryption algorithm 

## Future Plan
Features that will be added in the future:
- Support for the BIND command
- Support for the ASSOCIATE command

## Build
Build from source on Ubuntu 16.04:
```bash
# Install packages
$ sudo apt-get update && sudo apt-get install build-essential libssl-dev cmake -y

# Build from source
$ git clone https://github.com/senlinzhan/socks5.git
$ cd socks5
$ git submodule update --init
$ mkdir build && cd build
$ cmake ..
$ make
```
