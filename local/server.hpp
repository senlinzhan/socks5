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

#include <string>

/**
   Forward declaration
 **/
struct event_base;
struct evconnlistener;
struct evdns_base;

class Server
{
public:
    Server(const std::string &host, unsigned short port,
           const std::string &remoteHost, unsigned short remotePort,
           const std::string &key);
    
    ~Server();
    
    // disable the copy operations    
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    void createTunnel(int inConnFd);
    
    // run the event loop
    void run();
    
private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
    evdns_base        *dns_;            // dns resolver
    
    std::string       remoteHost_;      // hostname of the proxy server
    unsigned short    remotePort_;      // listening port of the proxy server
    
    std::string       key_;             // secret key
};

#endif /* SERVER_H */
