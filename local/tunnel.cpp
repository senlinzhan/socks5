/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "tunnel.hpp"

#include <assert.h>
#include <glog/logging.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

static void inConnReadCallback(bufferevent *inConn, void *arg)
{
    assert(arg != nullptr);
    
    auto tunnel = static_cast<Tunnel *>(arg);    
    tunnel->encryptTransfer();
}

static void inConnEventCallback(bufferevent *bev, short what, void *arg)
{
    assert(arg != nullptr);
    
    auto tunnel = static_cast<Tunnel *>(arg);
    auto fd = tunnel->clientFd();
    
    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Client-" << fd << " close connection";
        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Client-" << fd << " connection error: "
                   << evutil_socket_error_to_string(err);
        
        delete tunnel;
    }
}

static void outConnReadCallback(bufferevent *outConn, void *arg)
{
    assert(arg != nullptr);
    
    auto tunnel = static_cast<Tunnel *>(arg);
    tunnel->decryptTransfer();    
}

static void outConnEventCallback(bufferevent *outConn, short what, void *arg)
{
    assert(arg != nullptr);
    
    auto tunnel = static_cast<Tunnel *>(arg);
    auto fd = tunnel->clientFd();
    
    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Proxy server close connection of client-" << fd;        
        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Connect to proxy server error for client-" << fd
                   << ": " << evutil_socket_error_to_string(err);
        
        delete tunnel;
    }    
}

Tunnel::Tunnel(std::shared_ptr<ServerBase> base, int inConnFd,
               const Address &address, const std::string &key)
    : base_(base),
      inConnFd_(inConnFd),
      inConn_(nullptr),
      outConn_(nullptr),
      cryptor_(key, "0000000000000000")  // FIXME: use random initialized vector
{
    inConn_ = base_->acceptConnection(
        inConnFd_, inConnReadCallback, inConnEventCallback, this
    );
    
    if (inConn_ != nullptr)
    {
        /**
           if we can't create the outgoing connection,
           we need to free the incoming connection
        **/
        outConn_ = base_->createConnection(
            address, outConnReadCallback, outConnEventCallback, this
        );        
        if (outConn_ == nullptr)
        {
            bufferevent_free(inConn_);
            inConn_ = nullptr;
        }
    }
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


void Tunnel::encryptTransfer()
{
    assert(inConn_ != nullptr);
    assert(outConn_ != nullptr);

    LOG(INFO) << "Encrypt and transfer data from client-"
              << inConnFd_ << " to the proxy server";
    
    cryptor_.encryptTransfer(inConn_, outConn_);
}

void Tunnel::decryptTransfer()
{
    assert(inConn_ != nullptr);
    assert(outConn_ != nullptr);
    
    LOG(INFO) << "Decrypt and transfer data from proxy server to the client-"
              << inConnFd_;
    
    cryptor_.decryptTransfer(outConn_, inConn_);
}
