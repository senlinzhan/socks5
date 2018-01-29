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

#include <arpa/inet.h>

#include <string>
#include <vector>

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

    if (addressType == ADDRESS_TYPE_IPV4)
    {
        int requestLength = 6 + 4;
        
        if (inBuffLength < requestLength)
        {
            return State::incomplete;
        }
        else if (inBuffLength > requestLength)
        {
            return State::error;
        }

        evbuffer_drain(inBuff, 4);

        unsigned char rawAddr[4];
        unsigned short rawPort;
        
        evbuffer_remove(inBuff, rawAddr, 4);
        evbuffer_remove(inBuff, &rawPort, 2);

        char address[INET_ADDRSTRLEN];
        unsigned short port;
        
        ::inet_ntop(AF_INET, rawAddr, address, INET_ADDRSTRLEN);
        port = ntohs(rawPort);
    }
    else if (addressType == ADDRESS_TYPE_IPV6)
    {
        int requestLength = 6 + 16;
        if (inBuffLength < requestLength)
        {
            return State::incomplete;
        }
        else if (inBuffLength > requestLength)
        {
            return State::error;
        }

        evbuffer_drain(inBuff, 4);

        unsigned char rawAddr[16];
        unsigned short port;
        
        evbuffer_remove(inBuff, rawAddr, 16);
        evbuffer_remove(inBuff, &port, 2);

        char address[INET6_ADDRSTRLEN];        
        ::inet_ntop(AF_INET6, rawAddr, address, INET_ADDRSTRLEN);
        port = ntohs(port);
    }
    else
    {
        if (inBuffLength < 5)
        {
            return State::incomplete;
        }

        unsigned char data[5];        
        evbuffer_copyout(inBuff, data, 5);

        unsigned char domainLength = data[4];        
        if (inBuffLength < domainLength + 6 + 1)
        {
            return State::incomplete;
        }

        std::string domain(domainLength, '\0');
        unsigned short port;
        
        evbuffer_drain(inBuff, 5);
        evbuffer_remove(inBuff, &domain[0], domain.size());
        evbuffer_remove(inBuff, &port, 2);
        
        port = ntohs(port);        
    }
    
    return State::success;
}
