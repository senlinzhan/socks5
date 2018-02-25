#include "conn.hpp"

#include <assert.h>

#include <iomanip> // This might be necessary
#include <iostream>

#include <glog/logging.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

static void inConnReadCallback(bufferevent *inConn, void *arg)
{
    assert(arg != nullptr);
    
    auto conn = static_cast<Connection *>(arg);    
    conn->encryptTransfer();
}

static void inConnEventCallback(bufferevent *bev, short what, void *arg)
{
    assert(arg != nullptr);    
    auto conn = static_cast<Connection *>(arg);
    
    if (what & BEV_EVENT_EOF)
    {
        delete conn;
    }

    if (what & BEV_EVENT_ERROR)
    {
        delete conn;
    }
}

static void outConnReadCallback(bufferevent *outConn, void *arg)
{
    assert(arg != nullptr);

    auto conn = static_cast<Connection *>(arg);
    conn->decryptTransfer();    
}

static void outConnEventCallback(bufferevent *outConn, short what, void *arg)
{
    assert(arg != nullptr);    
    auto conn = static_cast<Connection *>(arg);
    
    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Connection closed by proxy server";
        delete conn;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Connection to proxy server error: " 
                   << evutil_socket_error_to_string(err);
        
        delete conn;
    }    
}

Connection::Connection(event_base *base, evdns_base *dns, int inConnFd,
                       const std::string &remoteHost, unsigned short remotePort,
                       const std::string &key)
    : base_(base),
      dns_(dns),
      inConnFd_(inConnFd),
      inConn_(nullptr),
      outConn_(nullptr),
      cryptor_(key, "0000000000000000")
{
    evutil_make_socket_nonblocking(inConnFd_);
    
    inConn_ = bufferevent_socket_new(base_, inConnFd_, BEV_OPT_CLOSE_ON_FREE);
    if (inConn_ == nullptr)
    {
        LOG(ERROR) << "Failed to create connection for client-" << inConnFd_;
        return;
    }
    bufferevent_setcb(inConn_, inConnReadCallback, nullptr, inConnEventCallback, this);
    
    outConn_ = bufferevent_socket_new(
        base,
        -1,
        BEV_OPT_CLOSE_ON_FREE
    );
    if (outConn_ == nullptr)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Create outgoing connection for client-" << inConnFd_
                   << " failed: " << evutil_socket_error_to_string(err);
        return;
    }
    bufferevent_setcb(outConn_, outConnReadCallback, nullptr, outConnEventCallback, this);
    if (bufferevent_socket_connect_hostname(outConn_, dns_, AF_INET,
                                            remoteHost.c_str(), remotePort) == -1)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Connect to remote server for client-" << inConnFd_
                   << " failed: " << evutil_socket_error_to_string(err);
        return;
    }
    
    bufferevent_enable(inConn_, EV_READ | EV_WRITE);    
    bufferevent_enable(outConn_, EV_READ | EV_WRITE);    
}

Connection::~Connection()
{
    if (inConn_ != nullptr)
    {
        bufferevent_free(inConn_);
    }
    
    if (outConn_ != nullptr)
    {
        bufferevent_free(outConn_);
    } 
}


void Connection::encryptTransfer()
{ 
    cryptor_.encryptTransfer(inConn_, outConn_);
}

void Connection::decryptTransfer()
{
    auto buffer = cryptor_.readFrom(outConn_);    
    auto a = cryptor_.decrypt(buffer.data(), buffer.size());
    if (a != nullptr)
    {
        std::cerr << "Content: " << std::hex;    
        for (auto c: *a)
        {
            std::cerr << int(c) << " ";
        }
        std::cerr << std::endl;    
    }
    else
    {
        std::cerr << "ERROR" << std::endl;
    }
    
    cryptor_.decryptTransfer(outConn_, inConn_);
}
