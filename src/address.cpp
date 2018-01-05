/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "address.hpp"

#include <arpa/inet.h>

Address::Address(struct sockaddr *address)
    : type_(Type::unknown)
{
    if (address->sa_family == AF_INET)
    {
        auto sin = reinterpret_cast<sockaddr_in *>(address);
        ip_.reserve(INET_ADDRSTRLEN);

        if (::inet_ntop(AF_INET, &sin->sin_addr, &ip_[0], INET_ADDRSTRLEN) != nullptr)
        {
            type_ = Type::ipv4;
            port_ = ntohs(sin->sin_port);            
        }
    }
    else if (address->sa_family == AF_INET6)
    {
        auto sin = reinterpret_cast<sockaddr_in6 *>(address);
        ip_.reserve(INET6_ADDRSTRLEN);
        
        if (::inet_ntop(AF_INET, &sin->sin6_addr, &ip_[0], INET6_ADDRSTRLEN) != nullptr)
        {
            type_ = Type::ipv6;
            port_ = ntohs(sin->sin6_port);            
        }
    }
}

std::string Address::ip() const
{
    return ip_;
}

uint16_t Address::port() const
{
    return port_;
}

std::string Address::toString() const
{
    return ip_ + ":" + std::to_string(port_);
}

Address::Type Address::type() const
{
    return type_;
}

std::ostream &operator<<(std::ostream &os, const Address &addr)
{
    os << addr.toString();
    return os;
}
