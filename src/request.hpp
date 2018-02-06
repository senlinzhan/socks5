#ifndef REQUEST_H
#define REQUEST_H

#include "address.hpp"

/**
   Forward declaration
 **/
struct  bufferevent;
struct  evdns_base;
class   Tunnel;

class Request 
{
public:
    static constexpr unsigned char SOCKS5_VERSION                   = 0x05;
    
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
    
    enum class State {incomplete, success, error};
    
    Request(evdns_base *dns, Tunnel *tunnel);

    // disable the copy operations
    Request(const Request &) = delete;
    Request &operator=(const Request &) = delete;

    // Handle client request
    State handleRequest();

    // Send reply to client when error occured
    static void replyForError(bufferevent *inConn, unsigned char code);   
    
    // Send reply to client connection when success
    static void replyForSuccess(bufferevent *inConn, const Address &address);    
private:
    // Send reply to client connection
    static void sendReply(bufferevent *inConn, unsigned char code, const Address &address);
    
    // Read destination address
    State readAddress(unsigned char addressType, Address &address);

    // Handle CONNECT command
    State handleConnect(const Address &address);

    // Handle BIND command    
    State handleBind();

    // Handle UDP ASSOCIATE command
    State handleUDPAssociate();
 
    evdns_base    *dns_;
    Tunnel        *tunnel_;
    bufferevent   *inConn_;
};

#endif /* REQUEST_H */
