/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
   Forward declaration
 **/
struct  bufferevent;
class   Tunnel;

class Protocol
{
public:
    Protocol(Tunnel *tunnel);

    void readClientProtocol(bufferevent *clientBev);
    
private:
    Tunnel    *tunnel_;
};

#endif /* PROTOCOL_H */
