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

    int clientID = tunnel->clientID();
    
    if (tunnel->state() == Tunnel::State::init)
    {
        LOG(INFO) << "Handle Authentication for client-" << clientID;
        
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
        auto state = tunnel->handleRequest(inConn);
        if (state == Request::State::success)
        {
            tunnel->setState(Tunnel::State::waitForConnect);
        }
        else if (state == Request::State::error)
        {
            delete tunnel;
        }
        else
        {
            // the data received is incomplete, nothing to do here
            assert(state == Request::State::incomplete);            
        }
    }
    else if (tunnel->state() == Tunnel::State::waitForConnect)
    {
        /** 
            Waiting for establishing connection to the server,
            at this point the clien can't send any data to the socks5 server
         **/
        delete tunnel;
    }
    else if (tunnel->state() == Tunnel::State::connected)
    {
        auto outConn = tunnel->outConnection();        
        bufferevent_read_buffer(inConn, bufferevent_get_output(outConn));
        
        LOG(INFO) << "Transfer data from client-" << clientID << " to server";
    }
    else if (tunnel->state() == Tunnel::State::clientMustClose)
    {
        LOG(ERROR) << "At this point the client-" << clientID
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

    int clientID = tunnel->clientID();    
    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Client-" << clientID << " close connection";           

        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Client-" << clientID << " connection error: "
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

int Tunnel::clientID() const
{
    return inConnFd_;
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
    
    Request request(dns_, this);
    return request.handleRequest();
}

bufferevent *Tunnel::inConnection() const
{
    assert(inConn_ != nullptr);
    
    return inConn_;
}

bufferevent *Tunnel::outConnection() const
{
    assert(outConn_ != nullptr);
    
    return outConn_;
}

void Tunnel::setOutConnection(bufferevent *outConn)
{
    assert(outConn != nullptr);
    assert(outConn_ == nullptr);

    outConn_ = outConn;
}
