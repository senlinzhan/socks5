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

#include "base.hpp"
#include "cipher.hpp"

class Tunnel
{
public:
    Tunnel(std::shared_ptr<ServerBase> base, int inConnFd,
           const std::string &remoteHost, unsigned short remotePort,
           const std::string &key);

    ~Tunnel();
    
    // disable the copy operations    
    Tunnel(const Tunnel &) = delete;
    Tunnel &operator=(const Tunnel &) = delete;

    // Encrypt and transfer data from client to the proxy server
    void encryptTransfer();

    // Decrypt and transfer data from proxy server to the client
    void decryptTransfer();

    // Return the client socket descriptor
    inline int clientFd() const
    {
        return inConnFd_;
    }
    
private:    
    std::shared_ptr<ServerBase>  base_;

    int                          inConnFd_;       // client socket descriptor
    bufferevent                  *inConn_;        // incoming connection
    bufferevent                  *outConn_;       // outgoing connection
    
    Cryptor                      cryptor_;
};

#endif /* TUNNEL_H */
