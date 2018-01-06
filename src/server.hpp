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

#include <gflags/gflags.h>

/**
   Forward declaration
 **/
struct event_base;
struct evconnlistener;

class Server
{
public:
    Server(const std::string &host, gflags::int32 port);
    ~Server();

    // disable the copy operations
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // run the event loop
    void run();

private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
};

#endif /* SERVER_H */
