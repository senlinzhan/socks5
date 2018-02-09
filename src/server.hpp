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

#include "config.hpp"

#include <gflags/gflags.h>

/**
   Forward declaration
 **/
struct event_base;
struct evconnlistener;
struct evdns_base;

class Server
{
public:
    Server(const Config &config);
    ~Server();

    // disable the copy operations
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // run the event loop
    void run();

    // Return configuration
    Config config() const;

    // Return DNS resolver 
    evdns_base *dns() const;

private:
    Config            config_;
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
    evdns_base        *dns_;            // dns resolver
};

#endif /* SERVER_H */
