/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "tunnel.hpp"

#include <glog/logging.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

static void inConnReadCallback(bufferevent *bev, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (bev == nullptr || tunnel == nullptr)
    {
        LOG(ERROR) << "inConnReadCallback receive invalid arguments";
        return;
    }

    if (tunnel->state() == Tunnel::State::init)
    {
        tunnel->initConnWithClient(bev);
    }
}

static void inConnEventCallback(bufferevent *bev, short what, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (bev == nullptr || tunnel == nullptr)
    {
        LOG(ERROR) << "inConnEventCallback receive invalid arguments";
        return;
    }

    auto fd = bufferevent_getfd(bev);
    
    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Client-" << fd << " close connection";           

        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(INFO) << "Client-" << fd << " connection error: "
                  << evutil_socket_error_to_string(err);

        delete tunnel;
    }
}

static void outConnReadCallback(bufferevent *bev, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (bev == nullptr || tunnel == nullptr)
    {
        LOG(ERROR) << "outConnReadCallback receive invalid arguments";
        return;
    }    
}

/**
   Called when bufferevent wirte all it's data to the peer
 **/
static void closeOnWriteComplete(bufferevent *bev, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (bev == nullptr || tunnel == nullptr)
    {
        LOG(ERROR) << "closeOnWriteComplete receive invalid arguments";
        return;
    }
    
    auto output = bufferevent_get_output(bev);
    
    auto outputLength = evbuffer_get_length(output);
    if (outputLength == 0)
    {
        bufferevent_free(bev);
    }
}

Tunnel::Tunnel(event_base *base, int inConnFd)
    : base_(base),
      inConnFd_(inConnFd),
      inConn_(nullptr),
      outConn_(nullptr),
      state_(State::init),
      protocol_(this)
{
    evutil_make_socket_nonblocking(inConnFd_);

    inConn_ = bufferevent_socket_new(base_, inConnFd_, BEV_OPT_CLOSE_ON_FREE);
    if (inConn_ == nullptr)
    {
        LOG(ERROR) << "Failed to create connection for client-" << inConnFd_;
        return;
    }
    
    bufferevent_setcb(inConn_, inConnReadCallback, nullptr, inConnEventCallback, this);
    if (bufferevent_enable(inConn_, EV_READ|EV_WRITE) != 0)
    {
        LOG(ERROR) << "Failed to enable read/write on client-" << inConnFd_;
        return;
    }
}

Tunnel::State Tunnel::state() const
{
    return state_;
}

Tunnel::~Tunnel()
{
    LOG(INFO) << "Free client-" << inConnFd_;
    
    if (inConn_ != nullptr)
    {
        bufferevent_free(inConn_);
    }

    if (outConn_ != nullptr)
    {
        bufferevent_free(outConn_);
    }
}

void Tunnel::initConnWithClient(bufferevent *bev)
{
    protocol_.readClientProtocol(bev);
}
