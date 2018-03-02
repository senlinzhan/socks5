#include "sockets.hpp"
#include "tunnel.hpp"
#include "request.hpp"

#include <assert.h>
#include <array>
#include <algorithm>

#include <glog/logging.h>

#include <event2/event.h>
#include <event2/dns.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
 
Request::Request(const Cryptor &cryptor, evdns_base *dns, Tunnel *tunnel)
    : cryptor_(cryptor),
      dns_(dns),
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

    auto data = cryptor_.decryptFrom(inConn_);
    if (data == nullptr)
    {
        return State::error;
    }

    auto size = data->size();
    if (size < 4)
    {
        return State::incomplete;
    }
    
    unsigned char version = (*data)[0];
    unsigned char command = (*data)[1];
    unsigned char addressType = (*data)[3];

    // check protocol version
    if (version != SOCKS5_VERSION)
    {
        return State::error;
    }

    Address address;
    auto state = readAddress(addressType, address, data);
    if (state != State::success)
    {
        return state;
    }
    cryptor_.removeFrom(inConn_);
    
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
        replyForError(cryptor_, inConn_, REPLY_COMMAND_NOT_SUPPORTED);
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
Request::State Request::readAddress(unsigned char addressType, Address &address, Cryptor::BufferPtr &data)
{
    // check address type
    if (addressType != ADDRESS_TYPE_IPV4 &&
        addressType != ADDRESS_TYPE_IPV6 &&
        addressType != ADDRESS_TYPE_DOMAIN_NAME)
    {
        replyForError(cryptor_, inConn_, REPLY_ADDRESS_TYPE_NOT_SUPPORTED);        
        return State::error;
    }
    
    unsigned short port;
    if (addressType == ADDRESS_TYPE_IPV4)
    {
        if (data->size() < 10)
        {
            return State::incomplete;
        }
        else if (data->size() > 10)
        {
            return State::error;
        }

        std::array<unsigned char, 4> rawAddr;        
        std::copy(data->begin() + 4, data->begin() + 8, rawAddr.data());
        std::copy(data->begin() + 8, data->end(),
                  reinterpret_cast<unsigned char *>(&port));

        address = Address(rawAddr, port);
    }
    else if (addressType == ADDRESS_TYPE_IPV6)
    {
        if (data->size() < 22)
        {
            return State::incomplete;
        }
        else if (data->size() > 22)
        {
            return State::error;
        }
        
        std::array<unsigned char, 16> rawAddr;
        std::copy(data->begin() + 4, data->begin() + 20, rawAddr.data());
        std::copy(data->begin() + 20, data->end(),
                  reinterpret_cast<unsigned char *>(&port));
        
        address = Address(rawAddr, port);
    }
    else
    {
        if (data->size() < 5)
        {
            return State::incomplete;
        }        

        int domainLength = (*data)[4];
        if (data->size() < domainLength + 7)
        {
            return State::incomplete;
        }
        else if (data->size() > domainLength + 7)
        {
            return State::error;            
        }

        std::string domain(domainLength, '\0');
        std::copy(data->begin() + 5, data->begin() + 5 + domainLength, &domain[0]);   
        std::copy(data->begin() + 5 + domainLength, data->end(),
                  reinterpret_cast<unsigned char *>(&port));
        
        address = Address(domain, port);
    }

    if (!address.isValid())
    {
        return State::error;
    }

    LOG(INFO) << "Read destination address: " << address;
    return State::success;
}

void Request::replyForError(const Cryptor &cryptor, bufferevent *inConn, unsigned char code)
{
    assert(inConn != nullptr);
    assert(code != REPLY_SUCCESS);
     
    return sendReply(cryptor, inConn, code, Address());
}

void Request::replyForSuccess(const Cryptor &cryptor, bufferevent *inConn, const Address &address)
{
    assert(inConn != nullptr);
    assert(address.type() != Address::Type::domain);
    assert(address.type() != Address::Type::unknown);
    
    return sendReply(cryptor, inConn, REPLY_SUCCESS, address);
}

void Request::sendReply(const Cryptor &cryptor, bufferevent *inConn, unsigned char code, const Address &address)
{
    unsigned char reply[4];

    reply[0] = SOCKS5_VERSION;
    reply[1] = code;
    reply[2] = 0x00;

    std::vector<unsigned char> data;
    std::array<unsigned char, 2> port;
    
    if (address.type() == Address::Type::ipv4)
    {
        reply[3] = ADDRESS_TYPE_IPV4;        
        auto ip = address.toRawIPv4();
        port = address.rawPortNetworkOrder();
        
        data.insert(data.end(), std::begin(reply), std::end(reply));
        data.insert(data.end(), std::begin(ip), std::end(ip));
    }
    else if (address.type() == Address::Type::ipv6)
    {
        reply[3] = ADDRESS_TYPE_IPV6;
        auto ip = address.toRawIPv6();
        port = address.rawPortNetworkOrder();
        
        data.insert(data.end(), std::begin(reply), std::end(reply));
        data.insert(data.end(), std::begin(ip), std::end(ip));
    }
    else
    {
        reply[3] = ADDRESS_TYPE_IPV4;        
        std::array<unsigned char, 4> ip = {{ 0, 0, 0, 0 }};
        port = {{ 0, 0 }};
        
        data.insert(data.end(), std::begin(reply), std::end(reply));
        data.insert(data.end(), std::begin(ip), std::end(ip));
    }

    data.insert(data.end(), std::begin(port), std::end(port));    
    cryptor.encryptTo(inConn, data.data(), data.size());            
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
    replyForError(cryptor_, inConn_, REPLY_COMMAND_NOT_SUPPORTED);
    
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
    replyForError(cryptor_, inConn_, REPLY_COMMAND_NOT_SUPPORTED);
    
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

    LOG(INFO) << "Transfer data from server to client-" << tunnel->clientID();
    auto buff = tunnel->cryptor().readFrom(outConn);
    std::cerr << "Content: " << std::hex;    
    for (auto c: buff)
    {
        std::cerr << int(c) << " ";
    }
    std::cerr << std::endl;    
    
    tunnel->encryptTransfer();
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
            Request::replyForSuccess(tunnel->cryptor(), inConn, addr);
            tunnel->setState(Tunnel::State::connected);
            
            LOG(INFO) << "Connect to destination success for client-" << clientID;
        }
        else
        {
            Request::replyForError(tunnel->cryptor(), inConn, Request::REPLY_SERVER_FAILURE);
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
        replyForError(cryptor_, inConn_, REPLY_SERVER_FAILURE);
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
            replyForError(cryptor_, inConn_, REPLY_NETWORK_UNREACHABLE);
        }
        else if (err == ECONNREFUSED)
        {
            replyForError(cryptor_, inConn_, REPLY_CONNECTIONREFUSED);
        }
        else
        {
            replyForError(cryptor_, inConn_, REPLY_HOST_UNREACHABLE);
        }
        
        return State::error;            
    }
     
    return State::success;    
}
