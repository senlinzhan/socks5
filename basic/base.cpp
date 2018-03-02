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

ServerBase::ServerBase(const Address &address, AcceptCallback callback,
                       AcceptErrorCallback errorCallback)
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
    int listeningSocket = createListeningSocket(address.host(), address.portString());
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

bufferevent *ServerBase::acceptConnection(evutil_socket_t inConnFd, DataCallback callback,
                                          EventCallback eventCallback, void *arg)
{
    evutil_make_socket_nonblocking(inConnFd);

    auto inConn = bufferevent_socket_new(base_, inConnFd, BEV_OPT_CLOSE_ON_FREE);
    if (inConn == nullptr)
    {
        int err = EVUTIL_SOCKET_ERROR();        
        LOG(ERROR) << "Failed to create connection for client-" << inConnFd
                   << ": " << evutil_socket_error_to_string(err);
        
        return nullptr;
    }
    
    bufferevent_setcb(inConn, callback, nullptr, eventCallback, arg);
    if (bufferevent_enable(inConn, EV_READ|EV_WRITE) != 0)
    {
        LOG(ERROR) << "Failed to enable read/write for client-" << inConnFd;
        return nullptr;
    }

    return inConn;
}

bufferevent *ServerBase::createConnection(const Address &address, DataCallback callback,
                                          EventCallback eventCallback, void *arg)
{
    if (address.type() == Address::Type::unknown)
    {
        return nullptr;
    }
    
    // create outgoing connection
    auto outConn = bufferevent_socket_new(
        base_,
        -1,
        BEV_OPT_CLOSE_ON_FREE
    );
    if (outConn == nullptr)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Failed to create outgoing connection to " << address
                   << ": " << evutil_socket_error_to_string(err);
        
        return nullptr;
    }

    // setup callbacks
    bufferevent_setcb(outConn, callback, nullptr, eventCallback, arg);

    int af;
    if (address.type() == Address::Type::ipv4)
    {
        af = AF_INET;
    }
    else if (address.type() == Address::Type::ipv6)
    {
        af = AF_INET6;
    }
    else
    {
        af = AF_UNSPEC;
    }

    // connect to remote server
    if (bufferevent_socket_connect_hostname(outConn, dns_, af,
                                            address.host().c_str(),
                                            address.port()) == -1)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Failed to connect the remote server " << address
                   << ": " << evutil_socket_error_to_string(err);
        
        return nullptr;
    }

    if (bufferevent_enable(outConn, EV_READ | EV_WRITE) != 0)
    {
        LOG(ERROR) << "Failed to enable read/write for outgoing connection-"
                   << bufferevent_getfd(outConn);
        
        return nullptr;
    }

    return outConn;
}
