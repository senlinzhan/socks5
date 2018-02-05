#include "request.hpp"

#include <assert.h>
#include <array>

#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

Request::Request(evdns_base *dns, struct bufferevent *inConn)
    : dns_(dns),
      inConn_(inConn)
{
    assert(dns_ != nullptr);
    assert(inConn_ != nullptr);
}
 
/**
  The SOCKS5 request is formed as follows:
  +----+-----+-------+------+----------+----------+
  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
  +----+-----+-------+------+----------+----------+
  | 1  |  1  | X'00' |  1   | Variable |    2     |
  +----+-----+-------+------+----------+----------+
**/
Request::State Request::handleRequest()
{
    if (inConn_ == nullptr)
    {
        return State::error;
    }

    auto inBuff = bufferevent_get_input(inConn_);
    auto inBuffLength = evbuffer_get_length(inBuff);
    
    if (inBuffLength < 4)
    {
        return State::incomplete;
    }

    // copy the first 4 bytes
    unsigned char request[4];    
    evbuffer_copyout(inBuff, request, 4);
    
    unsigned char version = request[0];
    unsigned char command = request[1];
    unsigned char addressType = request[3];

    // check protocol version
    if (version != SOCKS5_VERSION)
    {
        return State::error;
    }

    Address address;
    auto state = readAddress(addressType, address);
    if (state != State::success)
    {
        return state;
    }

    if (command == CMD_CONNECT)
    {
        return handleConnect(address);
    }
    else if (command == CMD_BIND)
    {
        return handleBind();
    }
    else if (command == CMD_UDP_ASSOCIATE)
    {
        return handleUDPAssociate();
    }
    else
    {
        sendReply(REPLY_COMMAND_NOT_SUPPORTED);
        return State::error;        
    }
    
    return State::success;
}

/**
   Read address

   Returns:
     State::incomplete   the data received by server is incomplete
     State::success      read address success
     State::error        an error occurred
**/
Request::State Request::readAddress(unsigned char addressType, Address &address)
{
    // check address type
    if (addressType != ADDRESS_TYPE_IPV4 &&
        addressType != ADDRESS_TYPE_IPV6 &&
        addressType != ADDRESS_TYPE_DOMAIN_NAME)
    {
        sendReply(REPLY_ADDRESS_TYPE_NOT_SUPPORTED);        
        return State::error;
    }
    
    auto inBuff = bufferevent_get_input(inConn_);
    auto inBuffLength = evbuffer_get_length(inBuff);

    unsigned short port;
    if (addressType == ADDRESS_TYPE_IPV4)
    {
        if (inBuffLength < 10)
        {
            return State::incomplete;
        }
        else if (inBuffLength > 10)
        {
            return State::error;
        }
        
        evbuffer_drain(inBuff, 4);

        std::array<unsigned char, 4> rawAddr;
        evbuffer_remove(inBuff, &rawAddr[0], rawAddr.size());
        evbuffer_remove(inBuff, &port, 2);

        address = Address(rawAddr, port);
    }
    else if (addressType == ADDRESS_TYPE_IPV6)
    {
        if (inBuffLength < 22)
        {
            return State::incomplete;
        }
        else if (inBuffLength > 22)
        {
            return State::error;
        }
        
        evbuffer_drain(inBuff, 4);

        std::array<unsigned char, 16> rawAddr;
        evbuffer_remove(inBuff, &rawAddr[0], rawAddr.size());
        evbuffer_remove(inBuff, &port, 2);

        address = Address(rawAddr, port);
    }
    else
    {
        if (inBuffLength < 5)
        {
            return State::incomplete;
        }
        
        unsigned char data[5];        
        evbuffer_copyout(inBuff, data, 5);

        int domainLength = data[4];
        if (inBuffLength < domainLength + 7)
        {
            return State::incomplete;
        }
        else if (inBuffLength > domainLength + 7)
        {
            return State::error;            
        }

        std::string domain(domainLength, '\0');
        
        evbuffer_drain(inBuff, 5);
        evbuffer_remove(inBuff, &domain[0], domain.size());
        evbuffer_remove(inBuff, &port, 2); 

        address = Address(domain, port);
    }

    if (!address.isValid())
    {
        return State::error;
    }
    
    return State::success;
}

void Request::sendReply(unsigned char code)
{
    unsigned char content[2];

    content[0] = SOCKS5_VERSION;
    content[1] = code;
    
    bufferevent_write(inConn_, content, 2);    
}

/**
   Handle BIND command
   
   Returns:
     State::success      success 
     State::error        an error occurred
**/
Request::State Request::handleBind()
{
    // FIXME: support BIND command
    sendReply(REPLY_COMMAND_NOT_SUPPORTED);
    
    return State::error;
}

/**
   Handle UDP ASSOCIATE command
   
   Returns:
     State::success      success 
     State::error        an error occurred
**/
Request::State Request::handleUDPAssociate()
{
    // FIXME: support UDP ASSOCIATE command
    sendReply(REPLY_COMMAND_NOT_SUPPORTED);
    
    return State::error;
}

/**
   Handle CONNECT command

   Returns:
     State::success      success 
     State::error        an error occurred   
 **/
Request::State Request::handleConnect(const Address &address)
{
    auto outConn = bufferevent_socket_new(
        bufferevent_get_base(inConn_),
        -1,
        BEV_OPT_CLOSE_ON_FREE
        );
    
    if (outConn == nullptr)
    {
        sendReply(REPLY_SERVER_FAILURE);
        return State::error;
    }
    
    //bufferevent_setcb(outConn, outConnReadCallback, nullptr, outConnEventCallback, tunnel_);

    int af;
    if (address.type() == Address::Type::ipv4)
    {
        af = AF_INET;
    }
    else if (address.type() == Address::Type::ipv6)
    {
        af = AF_INET6;
    }
    else
    {
        af = AF_UNSPEC;
    }
    
    if (bufferevent_socket_connect_hostname(outConn, dns_, af,
                                            address.host().c_str(),
                                            address.port()) == -1)
    {
        int err = EVUTIL_SOCKET_ERROR();

        if (err == ENETUNREACH)
        {
            sendReply(REPLY_NETWORK_UNREACHABLE);
        }
        else if (err == ECONNREFUSED)
        {
            sendReply(REPLY_CONNECTIONREFUSED);
        }
        else
        {
            sendReply(REPLY_HOST_UNREACHABLE);
        }
        
        return State::error;            
    }
     
    return State::success;    
}
