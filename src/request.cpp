#include "sockets.hpp"
#include "tunnel.hpp"
#include "request.hpp"

#include <assert.h>
#include <array>

#include <glog/logging.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
 
Request::Request(evdns_base *dns, Tunnel *tunnel)
    : dns_(dns),
      tunnel_(tunnel)
{    
    assert(dns_ != nullptr);
    assert(tunnel_ != nullptr);

    inConn_ = tunnel->inConnection();
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

    assert(evbuffer_get_length(inBuff) == 0);
    
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
        replyForError(inConn_, REPLY_COMMAND_NOT_SUPPORTED);
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
        replyForError(inConn_, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);        
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

    LOG(INFO) << "Read destination address: " << address;
    return State::success;
}

void Request::replyForError(bufferevent *inConn, unsigned char code)
{
    assert(inConn != nullptr);
    assert(code != REPLY_SUCCESS);
     
    return sendReply(inConn, code, Address());
}

void Request::replyForSuccess(bufferevent *inConn, const Address &address)
{
    assert(inConn != nullptr);
    assert(address.type() != Address::Type::domain);
    assert(address.type() != Address::Type::unknown);
    
    return sendReply(inConn, REPLY_SUCCESS, address);
}

void Request::sendReply(bufferevent *inConn, unsigned char code, const Address &address)
{
    unsigned char reply[4];

    reply[0] = SOCKS5_VERSION;
    reply[1] = code;
    reply[2] = 0x00;
    
    if (address.type() == Address::Type::ipv4)
    {
        reply[3] = ADDRESS_TYPE_IPV4;
        bufferevent_write(inConn, reply, 4);
        
        auto ip = address.toRawIPv4();
        auto port = address.portNetworkOrder();
        
        bufferevent_write(inConn, ip.data(), ip.size());
        bufferevent_write(inConn, &port, 2);                    
    }
    else if (address.type() == Address::Type::ipv6)
    {
        reply[3] = ADDRESS_TYPE_IPV6;
        bufferevent_write(inConn, reply, 4);

        auto ip = address.toRawIPv6();
        auto port = address.portNetworkOrder();
        
        bufferevent_write(inConn, ip.data(), ip.size());
        bufferevent_write(inConn, &port, 2);        
    }
    else
    {
        reply[3] = ADDRESS_TYPE_IPV4;        
        bufferevent_write(inConn, reply, 4);
        
        std::array<unsigned char, 4> ip = {{ 0, 0, 0, 0 }};
        unsigned short port = 0;

        bufferevent_write(inConn, ip.data(), ip.size());
        bufferevent_write(inConn, &port, 2);
    }
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
    replyForError(inConn_, REPLY_COMMAND_NOT_SUPPORTED);
    
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
    replyForError(inConn_, REPLY_COMMAND_NOT_SUPPORTED);
    
    return State::error;
}

static void outConnReadCallback(bufferevent *outConn, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (outConn == nullptr ||
        tunnel == nullptr ||
        tunnel->inConnection() == nullptr)
    {
        LOG(ERROR) << "inConnReadCallback receive invalid arguments";        
        return;
    }
    
    auto input = bufferevent_get_input(outConn);
    auto output = bufferevent_get_output(tunnel->inConnection());

    LOG(INFO) << "Transfer data from server to client-" << tunnel->clientID();
    
    evbuffer_add_buffer(output, input);
}

static void outConnEventCallback(bufferevent *outConn, short what, void *arg)
{
    auto tunnel = static_cast<Tunnel *>(arg);
    if (outConn == nullptr || tunnel == nullptr)
    {
        return;
    }

    int outConnFd = bufferevent_getfd(outConn);
    auto inConn = tunnel->inConnection();
    int clientID = tunnel->clientID();
    
    if (what & BEV_EVENT_CONNECTED)
    {       
        Address addr = getSocketLocalAddress(outConnFd);
        
        if (addr.type() == Address::Type::ipv4 ||
            addr.type() == Address::Type::ipv6)
        {
            Request::replyForSuccess(inConn, addr);
            tunnel->setState(Tunnel::State::connected);
            
            LOG(INFO) << "Connect to destination success for client-" << clientID;
        }
        else
        {
            Request::replyForError(inConn, Request::REPLY_SERVER_FAILURE);
            delete tunnel;
        }
    }

    if (what & BEV_EVENT_EOF)
    {
        LOG(INFO) << "Connection closed by server for client-" << clientID;
        delete tunnel;
    }

    if (what & BEV_EVENT_ERROR)
    {
        int err = EVUTIL_SOCKET_ERROR();
        LOG(ERROR) << "Connection to server error for client-" << clientID
                   << ": " << evutil_socket_error_to_string(err);
        
        delete tunnel;
    }    
}

/**
   Handle CONNECT command

   Returns:
     State::success      success 
     State::error        an error occurred   
 **/
Request::State Request::handleConnect(const Address &address)
{    
    LOG(INFO) << "Handle connect for client-" << tunnel_->clientID();
    
    auto outConn = bufferevent_socket_new(
        bufferevent_get_base(inConn_),
        -1,
        BEV_OPT_CLOSE_ON_FREE
    );
    
    if (outConn == nullptr)
    {
        replyForError(inConn_, REPLY_SERVER_FAILURE);
        return State::error;
    }
    
    tunnel_->setOutConnection(outConn);    
    bufferevent_setcb(outConn, outConnReadCallback, nullptr, outConnEventCallback, tunnel_);
    bufferevent_enable(outConn, EV_READ | EV_WRITE);
    
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
            replyForError(inConn_, REPLY_NETWORK_UNREACHABLE);
        }
        else if (err == ECONNREFUSED)
        {
            replyForError(inConn_, REPLY_CONNECTIONREFUSED);
        }
        else
        {
            replyForError(inConn_, REPLY_HOST_UNREACHABLE);
        }
        
        return State::error;            
    }
     
    return State::success;    
}
