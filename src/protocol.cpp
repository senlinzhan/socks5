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

#include <string>

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
    evbuffer_copyout(input, info.data(), 2);

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
    evbuffer_drain(input, 2);

    std::vector<unsigned char> methods(nmethods, 0);
    evbuffer_remove(input, methods.data(), nmethods);    

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
    
    if (bufferevent_write(clientBev, response.data(), response.size()) == -1)
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

bool Protocol::handleRequest(bufferevent *clietBev)
{
    
}
