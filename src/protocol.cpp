/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

/**
  Protocol of socks5: https://www.ietf.org/rfc/rfc1928.txt
 **/

#include "address.hpp"
#include "protocol.hpp"
#include "tunnel.hpp"
#include "sockets.hpp"

#include <assert.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

Protocol::Protocol(Tunnel *tunnel)
    : tunnel_(tunnel),
      address_(nullptr)
{    
}

static void outConnReadCallback(bufferevent *bev, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);

    if (bev == nullptr || tunnel == nullptr)
    {
        return;
    }

    // FIXME
    auto input = bufferevent_get_input(tunnel->inConn_);
    auto output = bufferevent_get_output(bev);
    evbuffer_add_buffer(output, input);
}

static void outConnEventCallback(bufferevent *bev, short what, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    
    if (bev == nullptr || tunnel == nullptr)
    {
        return;
    }

    unsigned char reply[4];
    reply[0] = Protocol::SOCKS5_VERSION;
    reply[1] = Protocol::REPLY_SUCCESS;
    reply[2] = 0x00;

    int outConnFd = bufferevent_getfd(bev);
    auto inConn = tunnel->inConnection();
    
    if (what & BEV_EVENT_CONNECTED)
    {
        Address addr = getSocketLocalAddress(outConnFd);
        if (addr.type() == Address::Type::ipv4)
        {
            reply[3] = Protocol::ADDRESS_TYPE_IPV4;

            auto ip = addr.toRawIPv4();
            auto port = addr.portNetworkOrder();
            
            bufferevent_write(inConn, reply, 4);
            bufferevent_write(inConn, ip.data(), ip.size());
            bufferevent_write(inConn, &port, 2);
        }
        else if (addr.type() == Address::Type::ipv6)
        {
            reply[3] = Protocol::ADDRESS_TYPE_IPV6;

            auto ip = addr.toRawIPv6();
            auto port = addr.portNetworkOrder();
            
            bufferevent_write(inConn, reply, 4);
            bufferevent_write(inConn, ip.data(), ip.size());
            bufferevent_write(inConn, &port, 2);            
        }
        else
        {
            reply[1] = Protocol::REPLY_SERVER_FAILURE;
            bufferevent_write(inConn, reply, 2);
        }
    }

    if (what & BEV_EVENT_EOF)
    {
        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        delete tunnel;
    }
}

/**
  The SOCKS request is formed as follows:
  +----+-----+-------+------+----------+----------+
  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
**/
Protocol::State Protocol::handleRequest(bufferevent *clientBev)
{
    int af;
    unsigned short port;
    
 
    auto outConn = bufferevent_socket_new(
        bufferevent_get_base(clientBev),
        -1,
        BEV_OPT_CLOSE_ON_FREE
        );
    
    if (outConn == nullptr)
    {
        reply[1] = REPLY_SERVER_FAILURE;
        bufferevent_write(clientBev, reply, 2);
        return State::error;
    }
    
    bufferevent_setcb(outConn, outConnReadCallback, nullptr, outConnEventCallback, tunnel_);
    
    auto dnsBase = evdns_base_new(
        bufferevent_get_base(clientBev),
        EVDNS_BASE_INITIALIZE_NAMESERVERS);
    
    if (bufferevent_socket_connect_hostname(outConn, dnsBase, af,
                                            address_->host().c_str(),
                                            port) == -1)
    {
        reply[1] = REPLY_SERVER_FAILURE;
        bufferevent_write(clientBev, reply, 2);
        return State::error;            
    }
    
        // tunnel_->setState(Tunnel::State::connected);
     
    return State::success;
}
