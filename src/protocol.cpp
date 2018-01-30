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


#include "protocol.hpp"
#include "tunnel.hpp"

#include <assert.h>
#include <arpa/inet.h>

#include <string>
#include <vector>

#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

Protocol::Protocol(Tunnel *tunnel)
    : tunnel_(tunnel),
      authMethod_(AUTH_NO_ACCEPTABLE)
{    
}

/**   
   The protocol used by the client to establish authentication:
   +----+----------+----------+
   |VER | NMETHODS | METHODS  |
   +----+----------+----------+
   | 1  |    1     | 1 to 255 |
   +----+----------+----------+

   Socks5 server response with:
   +----+--------+
   |VER | METHOD |
   +----+--------+
   | 1  |   1    |
   +----+--------+
 **/
bool Protocol::handleAuthentication(bufferevent *clientBev)
{
    auto inBuff = bufferevent_get_input(clientBev);
    auto inBuffLength = evbuffer_get_length(inBuff);

    if (inBuffLength < 2)
    {
        return true;
    }
    
    unsigned char info[2];
    evbuffer_copyout(inBuff, &info[0], 2);

    // check protocol version number
    if (info[0] != SOCKS5_VERSION)
    {
        return false;
    }

    // how many kinds of methods
    unsigned char nmethods = info[1];
    if (inBuffLength < 2 + nmethods)
    {
        return true;
    }
    else if (inBuffLength > 2 + nmethods)
    {
        return false;
    }

    // remove 2 bytes from input buffer
    evbuffer_drain(inBuff, 2);

    std::vector<unsigned char> methods(nmethods, 0);
    evbuffer_remove(inBuff, methods.data(), nmethods);    

    for (auto m: methods)
    {
        if (m == AUTH_NONE)
        {
            authMethod_ = AUTH_NONE;
            break;
        }
    }
    
    unsigned char response[2];
    response[0] = SOCKS5_VERSION;
    response[1] = authMethod_;
    
    if (bufferevent_write(clientBev, &response[0], 2) == -1)
    {
        return false;
    }

    if (authMethod_ == AUTH_NONE)
    {
        tunnel_->setState(Tunnel::State::authorized);        
    }
    else
    {
        tunnel_->setState(Tunnel::State::clientMustClose);
    }

    return true;
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

    if (what & BEV_EVENT_CONNECTED)
    {
        
    }

    if (what & BEV_EVENT_EOF)
    {
        
    }

    if (what & BEV_EVENT_ERROR)
    {
        
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
    if (clientBev == nullptr || tunnel_->state() != Tunnel::State::authorized)
    {
        return State::error;
    }

    auto inBuff = bufferevent_get_input(clientBev);
    auto inBuffLength = evbuffer_get_length(inBuff);
    
    if (inBuffLength < 4)
    {
        return State::incomplete;
    }

    // copy the first 4 bytes
    unsigned char request[4];    
    evbuffer_copyout(inBuff, request, 4);
    
    unsigned char version = request[0];
    unsigned char command = request[1];
    unsigned char addressType = request[3];
    
    if (version != SOCKS5_VERSION)
    {
        return State::error;
    }
    
    unsigned char reply[2] = {SOCKS5_VERSION, REPLY_SUCCESS};    
    if (!isValidCommand(command))
    {
        reply[1] = REPLY_COMMAND_NOT_SUPPORTED;
        bufferevent_write(clientBev, reply, 2);
        return State::error;
    }

    if (!isValidAddressType(addressType))
    {
        reply[1] = REPLY_ADDRESS_TYPE_NOT_SUPPORTED;
        bufferevent_write(clientBev, reply, 2);
        return State::error;        
    }

    std::string address;
    unsigned short port;
    int af;

    if (addressType == ADDRESS_TYPE_IPV4)
    {
        if (inBuffLength < 10)
        {
            return State::incomplete;
        }
        else if (inBuffLength > 10)
        {
            return State::error;
        }

        af = AF_INET;
        evbuffer_drain(inBuff, 4);

        unsigned char rawAddr[4];
        evbuffer_remove(inBuff, rawAddr, 4);
        evbuffer_remove(inBuff, &port, 2);

        address.resize(INET_ADDRSTRLEN);
        ::inet_ntop(AF_INET, rawAddr, &address[0], address.size());
        port = ntohs(port);
    }
    else if (addressType == ADDRESS_TYPE_IPV6)
    {
        if (inBuffLength < 22)
        {
            return State::incomplete;
        }
        else if (inBuffLength > 22)
        {
            return State::error;
        }

        af = AF_INET6;
        evbuffer_drain(inBuff, 4);

        unsigned char rawAddr[16];        
        evbuffer_remove(inBuff, rawAddr, 16);
        evbuffer_remove(inBuff, &port, 2);

        address.reserve(INET6_ADDRSTRLEN);
        ::inet_ntop(AF_INET6, rawAddr, &address[0], address.size());
        port = ntohs(port);
    }
    else
    {
        assert(addressType == ADDRESS_TYPE_DOMAIN_NAME);
        
        if (inBuffLength < 5)
        {
            return State::incomplete;
        }
        af = AF_UNSPEC;
        
        unsigned char data[5];        
        evbuffer_copyout(inBuff, data, 5);

        unsigned char domainLength = data[4];        
        if (inBuffLength < domainLength + 6 + 1)
        {
            return State::incomplete;
        }

        address.resize(domainLength);
        
        evbuffer_drain(inBuff, 5);
        evbuffer_remove(inBuff, &address[0], address.size());
        evbuffer_remove(inBuff, &port, 2);
        
        port = ntohs(port);        
    }

    if (command == CMD_CONNECT)
    {
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
                                                address.c_str(), port) == -1)
        {
            reply[1] = REPLY_SERVER_FAILURE;
            bufferevent_write(clientBev, reply, 2);
            return State::error;            
        }
        
        tunnel_->setState(Tunnel::State::connected);
    }
    else
    {
        // we only support CONNECT command here
        reply[1] = REPLY_COMMAND_NOT_SUPPORTED;
        bufferevent_write(clientBev, reply, 2);
        return State::error;        
    }
    
    
    return State::success;
}
