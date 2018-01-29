/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef PROTOCOL_H
#define PROTOCOL_H

/**
   Forward declaration
 **/
struct  bufferevent;
class   Tunnel;

class Protocol
{
public:
    enum class State { incomplete, success, error };
    
    Protocol(Tunnel *tunnel);

    bool handleAuthentication(bufferevent *clientBev);
    State handleRequest(bufferevent *clietBev);
    
private:
    static constexpr unsigned char SOCKS5_VERSION                   = 0x05;
    static constexpr unsigned char AUTH_NONE                        = 0x00;
    static constexpr unsigned char AUTH_NO_ACCEPTABLE               = 0xFF;

    static constexpr unsigned char CMD_CONNECT                      = 0x01;
    static constexpr unsigned char CMD_BIND                         = 0x02;
    static constexpr unsigned char CMD_UDP_ASSOCIATE                = 0x03;

    static constexpr unsigned char ADDRESS_TYPE_IPV4                = 0x01;
    static constexpr unsigned char ADDRESS_TYPE_DOMAIN_NAME         = 0x03;
    static constexpr unsigned char ADDRESS_TYPE_IPV6                = 0x04;

    static constexpr unsigned char REPLY_SUCCESS                    = 0x00;
    static constexpr unsigned char REPLY_SERVER_FAILURE             = 0x01;
    static constexpr unsigned char REPLY_RULE_FAILURE               = 0x02;
    static constexpr unsigned char REPLY_NETWORK_UNREACHABLE        = 0x03;
    static constexpr unsigned char REPLY_HOST_UNREACHABLE           = 0x04;
    static constexpr unsigned char REPLY_CONNECTIONREFUSED          = 0x05;
    static constexpr unsigned char REPLY_TTL_EXPIRED                = 0x06;
    static constexpr unsigned char REPLY_COMMAND_NOT_SUPPORTED      = 0x07;
    static constexpr unsigned char REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;
    
    inline bool isValidAddressType(unsigned char addressType)
    {
        return (addressType == ADDRESS_TYPE_IPV4 ||
                addressType == ADDRESS_TYPE_DOMAIN_NAME ||
                addressType == ADDRESS_TYPE_IPV6);
    }

    inline bool isValidCommand(unsigned char command)
    {
        return (command == CMD_CONNECT ||
                command == CMD_BIND ||
                command == CMD_UDP_ASSOCIATE);
    }
    
    Tunnel          *tunnel_;
    unsigned char   authMethod_;    
};

#endif /* PROTOCOL_H */
