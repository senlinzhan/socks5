#ifndef CONN_H
#define CONN_H

#include "cipher.hpp"

/**
   Forward declaration
 **/
struct  event_base;
struct  evdns_base;
struct  bufferevent;

class Connection
{
public:
    Connection(event_base *base, evdns_base *dns, int inConnFd, const std::string &remoteHost, unsigned short remotePort, const std::string &key);
    ~Connection();
    
    // disable the copy operations    
    Connection(const Connection &) = delete;
    Connection &operator=(const Connection &) = delete;
    
    void encryptTransfer();
    void decryptTransfer();
    
private:    
    event_base      *base_;
    evdns_base      *dns_;
    int             inConnFd_;
    bufferevent     *inConn_;
    bufferevent     *outConn_;
    Cryptor         cryptor_;
};

#endif /* CONN_H */
