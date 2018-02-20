/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "local.hpp"
#include "sockets.hpp"
#include "conn.hpp"

#include <event2/dns.h> 
#include <glog/logging.h>

#include <event2/listener.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>

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

    auto local = static_cast<Local *>(arg);
    local->createConnection(fd);
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

Local::Local(const std::string &host, unsigned short port,
             const std::string &remoteHost, unsigned short remotePort,
             const std::string &key)
    : base_(nullptr),
      listener_(nullptr),
      dns_(nullptr),
      remoteHost_(remoteHost),
      remotePort_(remotePort),
      key_(key)
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
    
    int listeningSocket = createListeningSocket(host, std::to_string(port));    
    if (listeningSocket == -1)
    {
        LOG(FATAL) << "failed to create listening socket";
    }

    LOG(INFO) << "Create listening socket - " << listeningSocket;
    
    listener_ = evconnlistener_new(
        base_,
        acceptCallback,
        this,
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

Local::~Local()
{
    evconnlistener_free(listener_);
    evdns_base_free(dns_, 1);     
    event_base_free(base_);    
}

/**
   Run the event loop
 **/
void Local::run()
{
    event_base_dispatch(base_);    
}

void Local::createConnection(int inConnFd)
{
    new Connection(base_, dns_, inConnFd, remoteHost_, remotePort_, key_);
}
