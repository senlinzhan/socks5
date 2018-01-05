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

#include <glog/logging.h>
#include <arpa/inet.h>

void acceptCallback(struct evconnlistener *listener, evutil_socket_t fd,
                    struct sockaddr *address, int socklen, void *arg)
{
    Address addr(address);
    if (addr.type() != Address::Type::unknown)
    {
        LOG(INFO) << "Accept new connection from: " << addr;
    }
    else
    {
        LOG(ERROR) << "Accept new connection from: unknown address";
    }
}

Server::Server(const std::string &host, gflags::int32 port)
    : base_(event_base_new()),
      listener_(nullptr)
{
    if (base_ == nullptr)
    {
        LOG(FATAL) << "failed to create event_base";
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
    
    listener_ = evconnlistener_new(
        base_,
        acceptCallback,
        nullptr,
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
}

void Server::run()
{
    event_base_dispatch(base_);    
}

Server::~Server()
{
    evconnlistener_free(listener_);
    event_base_free(base_);    
}
