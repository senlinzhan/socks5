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

    bool handleAuthentication(bufferevent *clientBev);
    bool handleRequest(bufferevent *clietBev);
    
private:
    static constexpr unsigned char SOCKS5_VERSION        = 0x05;
    static constexpr unsigned char AUTH_NONE             = 0x00;
    static constexpr unsigned char AUTH_NO_ACCEPTABLE    = 0xFF;

    Tunnel          *tunnel_;
    unsigned char   authMethod_;    
};

#endif /* PROTOCOL_H */
