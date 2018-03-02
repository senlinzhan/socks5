/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "address.hpp"

#include <assert.h>
#include <arpa/inet.h>
#include <string.h>

Address::Address()
    : type_(Type::unknown)
{    
}

Address::Address(struct sockaddr *address)
    : type_(Type::unknown)
{
    if (address->sa_family == AF_INET)
    {
        auto sin = reinterpret_cast<sockaddr_in *>(address);
        host_.resize(INET_ADDRSTRLEN, '\0');

        if (::inet_ntop(AF_INET, &sin->sin_addr, &host_[0], host_.size()) != nullptr)
        {
            type_ = Type::ipv4;
            port_ = ntohs(sin->sin_port);            
        }
    }
    else if (address->sa_family == AF_INET6)
    {
        auto sin = reinterpret_cast<sockaddr_in6 *>(address);
        host_.resize(INET6_ADDRSTRLEN, '\0');
        
        if (::inet_ntop(AF_INET6, &sin->sin6_addr, &host_[0], host_.size()) != nullptr)
        {
            type_ = Type::ipv6;
            port_ = ntohs(sin->sin6_port);            
        }
    }
}

Address::Address(const std::array<unsigned char, 4> &host, unsigned short port)
    : type_(Type::unknown),
      host_(INET_ADDRSTRLEN, '\0')
{
    if (::inet_ntop(AF_INET, host.data(), &host_[0], host_.size()) != nullptr)
    {
        type_ = Type::ipv4;
        port_ = ntohs(port);            
    }
}

Address::Address(const std::array<unsigned char, 16> &host, unsigned short port)
    : type_(Type::unknown),
      host_(INET6_ADDRSTRLEN, '\0')
{
    if (::inet_ntop(AF_INET6, host.data(), &host_[0], host_.size()) != nullptr)
    {
        type_ = Type::ipv6;
        port_ = ntohs(port);            
    }    
}

Address::Address(const std::string &domain, unsigned short port)
    : type_(Type::domain),
      host_(domain)
{
    port_ = ntohs(port);
}

Address Address::ConstructFromHostOrder(Type type, const std::string &host,
                                        unsigned short port)
{
    // TODO: check validation of hostname    

    Address address;
    address.type_ = type;
    address.host_ = host;
    address.port_ = port;
    
    return address;
}

std::string Address::host() const
{
    return host_;
}

uint16_t Address::port() const
{
    return port_;
}

std::string Address::toString() const
{
    return host_ + ":" + std::to_string(port_);
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
 
bool Address::isValid() const
{
    return type_ != Type::unknown;
}

std::array<unsigned char, 4> Address::toRawIPv4() const
{
    assert(type_ == Type::ipv4);

    std::array<unsigned char, 4> address;    
    ::inet_pton(AF_INET, host_.c_str(), address.data());
    
    return address;
}

std::array<unsigned char, 16> Address::toRawIPv6() const
{
    assert(type_ == Type::ipv6);

    std::array<unsigned char, 16> address;
    ::inet_pton(AF_INET6, host_.c_str(), address.data());    
    
    return address;    
}

unsigned short Address::portNetworkOrder() const
{
    return htons(port_);
}

std::array<unsigned char, 2> Address::rawPortNetworkOrder() const
{    
    std::array<unsigned char, 2> result;
    
    auto networkOrder = portNetworkOrder();
    memcpy(result.data(), &networkOrder, 2);

    return result;
}
