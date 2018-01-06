/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef TUNNEL_H
#define TUNNEL_H

#include "protocol.hpp"

/**
   Forward declaration
 **/
struct  event_base;
struct  bufferevent;

class Tunnel
{
public:
    enum class State { init, authorized, clientMustClose };
    
    Tunnel(event_base *base, int inConnFd);
    ~Tunnel();

    Tunnel(const Tunnel &) = delete;
    Tunnel &operator=(const Tunnel &) = delete;
    
    State state() const;
    void setState(State state);

    bool handleAuthentication(bufferevent *bev);
    bool handleRequest(bufferevent *bev);
    
private:
    event_base   *base_;

    int          inConnFd_;
    
    bufferevent  *inConn_;
    bufferevent  *outConn_;

    State        state_;
    Protocol     protocol_;
};

#endif /* TUNNEL_H */
