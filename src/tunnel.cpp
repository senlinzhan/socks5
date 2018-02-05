/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "auth.hpp"
#include "tunnel.hpp"

#include <assert.h>

#include <glog/logging.h>

#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

static void inConnReadCallback(bufferevent *inConn, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (inConn == nullptr || tunnel == nullptr)
    {
        LOG(ERROR) << "inConnReadCallback receive invalid arguments";
        return;
    }

    auto inConnFd = bufferevent_getfd(inConn);
    
    if (tunnel->state() == Tunnel::State::init)
    {
        auto state = tunnel->handleAuthentication(inConn);

        if (state == Auth::State::success)
        {
            tunnel->setState(Tunnel::State::authorized);
        }
        else if (state == Auth::State::failed)
        {
            // authentication failed, we let client close it's connection
            tunnel->setState(Tunnel::State::clientMustClose);            
        }
        else if (state == Auth::State::error)
        {
            // error occurred, we close client connection
            delete tunnel;
        }
        else
        {
            // the data received is incomplete, nothing to do here
            assert(state == Auth::State::incomplete);
        }

        return;
    }    
    else if (tunnel->state() == Tunnel::State::authorized)
    {
        /*
        if (!tunnel->handleRequest(inConn))
        {
            LOG(ERROR) << "Failed to handle request from client-" << inConnFd;
            delete tunnel;
        }
        */
    }
    else if (tunnel->state() == Tunnel::State::clientMustClose)
    {
        LOG(ERROR) << "At this point the client-" << inConnFd
                   << " shouldn't send any data";
        delete tunnel;
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

/**
   Called when bufferevent wirte all it's data to the peer
 **/
/**
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
**/

Tunnel::Tunnel(event_base *base, evdns_base *dns, int inConnFd)
    : base_(base),
      dns_(dns),
      inConnFd_(inConnFd),
      inConn_(nullptr),
      outConn_(nullptr),
      state_(State::init)
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

void Tunnel::setState(Tunnel::State state)
{
    state_ = state;
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

Auth::State Tunnel::handleAuthentication(bufferevent *inConn)
{
    assert(inConn == inConn_);
    
    Auth auth(inConn);
    return auth.authenticate();
}

Request::State Tunnel::handleRequest(bufferevent *inConn)
{
    assert(inConn == inConn_);
    
    Request request(dns_, inConn);
    return request.handleRequest();
}

bufferevent *Tunnel::inConnection() const
{
    return inConn_;
}
