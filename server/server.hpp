/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef SERVER_H
#define SERVER_H

#include "base.hpp"
#include "config.hpp"

#include <memory>

class Server
{
public:
    Server(const Config &config);

    // disable the copy operations
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // create the tunnel between the local server and the proxy server
    void createTunnel(int inConnFd);
    
    // run the event loop
    void run();

private:
    Config                       config_;
    std::shared_ptr<ServerBase>  base_;
};

#endif /* SERVER_H */
