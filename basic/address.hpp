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

#include <array>
#include <iostream>
#include <string>

class Address
{
public:
    enum Type { ipv4, ipv6, domain, unknown };

    // Construct an invalid address
    Address();
    
    explicit Address(struct sockaddr *address);

    /**
       Constructor for IPv4 Raw Address,
       both host and port are in network byte orders
    **/
    Address(const std::array<unsigned char, 4> &host, unsigned short port);

    /**
       Constructor for IPv6 Raw Address,
       both host and port are in network byte orders
    **/
    Address(const std::array<unsigned char, 16> &host, unsigned short port);
    
    /** 
        Constructor for domain name,
        port in network byte orders
     **/
    Address(const std::string &domain, unsigned short port);

    /**
       Factory constructor,
       note: both host and port are in host byte orders
    **/
    static Address ConstructFromHostOrder(Type type, const std::string &host,
                                          unsigned short port);
    
    // Return ip address or domain name
    std::string host() const;

    // Return port in host byte order
    std::uint16_t port() const;

    // Return string representation of host and port
    std::string toString() const;

    // Return type of address
    Type type() const;

    // Whether the address is valid
    bool isValid() const;

    // Return bytes representation of IPv4 address
    std::array<unsigned char, 4> toRawIPv4() const;

    // Return bytes representation of IPv6 address    
    std::array<unsigned char, 16> toRawIPv6() const;

    // Return port in network byte order
    unsigned short portNetworkOrder() const;

    // Return bytes representation of port
    std::array<unsigned char, 2> rawPortNetworkOrder() const;
    
private:
    Type          type_;
    std::string   host_;
    uint16_t      port_;
};

std::ostream &operator<<(std::ostream &os, const Address &addr);

#endif /* ADDRESS_H */
