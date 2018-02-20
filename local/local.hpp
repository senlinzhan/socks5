#ifndef LOCAL_H
#define LOCAL_H

#include <string>

/**
   Forward declaration
 **/
struct event_base;
struct evconnlistener;
struct evdns_base;

class Local
{
public:
    Local(const std::string &host, unsigned short port,
          const std::string &remoteHost, unsigned short remotePort,
          const std::string &key);
    ~Local();
    
    // disable the copy operations    
    Local(const Local &) = delete;
    Local &operator=(const Local &) = delete;

    void createConnection(int inConnFd);
    
    // run the event loop
    void run();
    
private:
    event_base        *base_;           // event loop
    evconnlistener    *listener_;       // tcp listener
    evdns_base        *dns_;            // dns resolver
    std::string       remoteHost_;
    unsigned short    remotePort_;
    std::string       key_;
};

#endif /* LOCAL_H */
