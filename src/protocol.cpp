/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "protocol.hpp"

Protocol::Protocol(Tunnel *tunnel)
    : tunnel_(tunnel)
{    
}

void Protocol::readClientProtocol(bufferevent *clientBev)
{
    auto inBuff = bufferevent_get_input(clientBev);
    auto inBuffLength = evbuffer_get_length(inBuff);

    if (inBuffLength < 1)
    {
        
    }
}
