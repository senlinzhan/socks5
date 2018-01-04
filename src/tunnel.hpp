#ifndef TUNNEL_H
#define TUNNEL_H

#include <event2/bufferevent.h>

class Tunnel
{
public:
    Tunnel(event_base *base);

    // disable the copy operations
    Tunnel(const Tunnel &) = delete;
    Tunnel &operator=(const Tunnel &) = delete;

private:
    event_base    *base_;
    bufferevent   *serverConn_;
    bufferevent   *clientConn_;
};




#endif /* TUNNEL_H */
