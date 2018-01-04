#ifndef SERVER_H
#define SERVER_H

#include <gflags/gflags.h>

#include <event2/listener.h>
#include <event2/bufferevent.h>

class Server
{
public:
    Server(const std::string &host, gflags::int32 port);
    ~Server();

    // disable the copy operations
    Server(const Server &) = delete;
    Server &operator=(const Server &) = delete;

    // run the event loop
    void run();

private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
};

#endif /* SERVER_H */
