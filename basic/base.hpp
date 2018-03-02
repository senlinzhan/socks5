/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef BASE_H
#define BASE_H

#include "address.hpp"

#include <string>

#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

using AcceptCallback      = evconnlistener_cb;
using AcceptErrorCallback = evconnlistener_errorcb;
using DataCallback        = bufferevent_data_cb;
using EventCallback       = bufferevent_event_cb;

class ServerBase
{
public:
    using Fd = evutil_socket_t;
    
    ServerBase(const std::string &host, unsigned short port,
               AcceptCallback callback, AcceptErrorCallback errorCallback);
    
    ~ServerBase();

    // disable the copy operations    
    ServerBase(const ServerBase &) = delete;
    ServerBase &operator=(const ServerBase &) = delete;
    
    // run the event loop
    void run();    

    // return the event loop
    event_base *base() const
    {
        return base_;
    }

    // return the dns resolver
    evdns_base *dns() const
    {
        return dns_;
    }

    bufferevent *acceptConnection(evutil_socket_t inConnFd, DataCallback callback,
                                  EventCallback eventCallback, void *arg);

    bufferevent *createConnection(const Address &address, DataCallback callback,
                                  EventCallback eventCallback, void *arg);
    
private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
    evdns_base        *dns_;            // dns resolver    
};

#endif /* BASE_H */
