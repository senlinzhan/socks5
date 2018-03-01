/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "base.hpp"
#include "sockets.hpp"

#include <glog/logging.h>

ServerBase::ServerBase(const std::string &host, unsigned short port,
                       AcceptCallback callback, AcceptErrorCallback errorCallback)
{
    // create the event loop
    base_ = event_base_new();    
    if (base_ == nullptr)
    {
        LOG(FATAL) << "Failed to create the event_base";
    }

    // create the dns resolver
    dns_ = evdns_base_new(base_, EVDNS_BASE_INITIALIZE_NAMESERVERS);
    if (dns_ == nullptr)
    {
        LOG(FATAL) << "Failed to create the dns resolver";        
    }

    // create the listening socket
    int listeningSocket = createListeningSocket(host, std::to_string(port));    
    if (listeningSocket == -1)
    {
        int err = EVUTIL_SOCKET_ERROR();        
        LOG(FATAL) << "Failed to create listening socket: "
                   << evutil_socket_error_to_string(err);
    }
    LOG(INFO) << "Create listening socket-" << listeningSocket;

    // create tcp lisnener
    listener_ = evconnlistener_new(
        base_,
        callback,
        this,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC,
        -1,
        listeningSocket
    );    
    if (listener_ == nullptr)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(FATAL) << "Failed to create listener: "
                   << evutil_socket_error_to_string(err);
    }

    // setup up error callback for the tcp listener
    evconnlistener_set_error_cb(listener_, errorCallback);    
}

ServerBase::~ServerBase()
{
    if (listener_ != nullptr)
    {
        evconnlistener_free(listener_);        
    }

    if (dns_ != nullptr)
    {
        evdns_base_free(dns_, 1);             
    }

    if (base_ != nullptr)
    {
        event_base_free(base_);            
    }
}


void ServerBase::run()
{
    event_base_dispatch(base_);    
}
