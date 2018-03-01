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

#include <string>

#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

using AcceptCallback = evconnlistener_cb;
using AcceptErrorCallback = evconnlistener_errorcb;

class ServerBase
{
public:
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
    
private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
    evdns_base        *dns_;            // dns resolver    
};

#endif /* BASE_H */
