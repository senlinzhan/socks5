/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "address.hpp"
#include "sockets.hpp"
#include "server.hpp"
#include "tunnel.hpp"

#include <event2/dns.h>
#include <event2/listener.h>

#include <glog/logging.h>
#include <arpa/inet.h>

/**
   Called when the server accept new connection
 **/
static void acceptCallback(evconnlistener *listener, evutil_socket_t fd,
                           sockaddr *address, int socklen, void *arg)
{
    Address addr(address);
    if (addr.type() == Address::Type::unknown)
    {
        LOG(ERROR) << "Accept new connection from: unknown address";
        return;
    }

    LOG(INFO) << "Accept new connection from: " << addr;

    auto base = evconnlistener_get_base(listener);
    auto dns = static_cast<evdns_base *>(arg);
     
    new Tunnel(base, dns, fd);       
}

/**
   Called when server accept failed
 **/
static void acceptErrorCallback(evconnlistener *listener, void *arg)
{
    auto base = evconnlistener_get_base(listener);
        
    int err = EVUTIL_SOCKET_ERROR();
    LOG(ERROR) << "got an error on the listener: "
               << evutil_socket_error_to_string(err);

    /**
       tells the event_base to stop looping 
       and still running callbacks for any active events
    **/
    event_base_loopexit(base, nullptr); 
}

Server::Server(const std::string &host, gflags::int32 port)
    : base_(nullptr),
      listener_(nullptr),
      dns_(nullptr)
{
    base_ = event_base_new();
    if (base_ == nullptr)
    {
        LOG(FATAL) << "failed to create event_base";
    }
    
    dns_ = evdns_base_new(base_, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    if (dns_ == nullptr)
    {
        LOG(FATAL) << "failed to create dns resolver";        
    }
    
    auto portStr = std::to_string(port);
    int listeningSocket = createListeningSocket(
        host.c_str(),
        portStr.c_str()
    );
    
    if (listeningSocket == -1)
    {
        LOG(FATAL) << "failed to create listening socket";
    }

    LOG(INFO) << "create listening socket - " << listeningSocket;
    
    listener_ = evconnlistener_new(
        base_,
        acceptCallback,
        dns_,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC,
        -1,
        listeningSocket
    );

    if (listener_ == nullptr)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(FATAL) << "failed to create listener: "
                   << evutil_socket_error_to_string(err);
    }

    evconnlistener_set_error_cb(listener_, acceptErrorCallback);
} 

/**
   Run the event loop
 **/
void Server::run()
{
    event_base_dispatch(base_);    
}

Server::~Server()
{
    evconnlistener_free(listener_);
    evdns_base_free(dns_, 1); 
    event_base_free(base_);    
}
