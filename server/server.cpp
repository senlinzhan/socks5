/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "address.hpp"
#include "server.hpp"
#include "tunnel.hpp"

#include <glog/logging.h>

/**
   Called when the server accept new connection
 **/
static void acceptCallback(evconnlistener *listener, evutil_socket_t inConnFd,
                           sockaddr *address, int socklen, void *arg)
{
    Address addr(address);
    if (addr.type() == Address::Type::unknown)
    {
        LOG(ERROR) << "Address of Client-" << inConnFd << " is unknown";
        return;
    }
    LOG(INFO) << "Accept new connection from: " << addr;
    
    auto server = static_cast<Server *>(arg);
    server->createTunnel(inConnFd);
}

/**
   Called when server accept failed
 **/
static void acceptErrorCallback(evconnlistener *listener, void *arg)
{        
    int err = EVUTIL_SOCKET_ERROR();
    LOG(ERROR) << "got an error on the listener: "
               << evutil_socket_error_to_string(err);

    /**
       tells the event_base to stop looping 
       and still running callbacks for any active events
    **/
    auto base = evconnlistener_get_base(listener);    
    event_base_loopexit(base, nullptr); 
}

Server::Server(const Config &config)
    : config_(config),
      base_(config.address(), acceptCallback, acceptErrorCallback)
{
} 

/**
   Run the event loop
 **/
void Server::run()
{
    base_.run();
}

void Server::createTunnel(int inConnFd)
{
    new Tunnel(config_, base_.base(), base_.dns(), inConnFd);    
}
