/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef ADDRESS_H
#define ADDRESS_H

#include <netinet/in.h>
#include <stdint.h>

#include <iostream>
#include <string>

class Address
{
public:
    enum Type { ipv4, ipv6, unknown };
    
    Address(struct sockaddr *address);

    std::string ip() const;
    std::uint16_t port() const;
    std::string toString() const;
    Type type() const;

private:
    Type          type_;
    std::string   ip_;
    uint16_t      port_;
};

std::ostream &operator<<(std::ostream &os, const Address &addr);

#endif /* ADDRESS_H */
