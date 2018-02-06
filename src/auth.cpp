#include "auth.hpp"

#include <vector>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

Auth::Auth(bufferevent *inConn)
    : inConn_(inConn),
      authMethod_(AUTH_NO_ACCEPTABLE),
      supportMethods_{AUTH_NONE}
{    
}

/**
   Handling client authentication

   Returns:
     State::incomplete   the data received by server is incomplete
     State::success      the authentication is successful
     State::failed       the authentication is failed
     State::error        an error occurred

   The protocol used by the client to establish authentication:
   +----+----------+----------+
   |VER | NMETHODS | METHODS  |
   +----+----------+----------+
   | 1  |    1     | 1 to 255 |
   +----+----------+----------+

   Socks5 server response with:
   +----+--------+
   |VER | METHOD |
   +----+--------+
   | 1  |   1    |
   +----+--------+
**/
Auth::State Auth::authenticate()
{
    auto inBuff = bufferevent_get_input(inConn_);
    auto inBuffLength = evbuffer_get_length(inBuff);

    if (inBuffLength < 2)
    {
        return State::incomplete;
    }

    unsigned char data[2];    
    evbuffer_copyout(inBuff, data, 2);

    // check protocol version number
    if (data[0] != SOCKS5_VERSION)
    {
        return State::error;
    }

    // how many kinds of methods
    unsigned char nmethods = data[1];

    if (inBuffLength < 2 + nmethods)
    {
        return State::incomplete;
    }    
    else if (inBuffLength > 2 + nmethods)
    {
        return State::error;
    }

    // remove first two bytes from the input buffer
    evbuffer_drain(inBuff, 2);

    std::vector<unsigned char> methods(nmethods, 0);
    evbuffer_remove(inBuff, methods.data(), nmethods);
    
    /* 
     * FIXME: we only support NO AUTHENTICATION here, 
     * add username/password authentication
     */    
    for (auto method: methods)
    {
        if (supportMethods_.find(method) != supportMethods_.end())
        {
            authMethod_ = method;
            break;
        }
    }

    unsigned char response[2];
    response[0] = SOCKS5_VERSION;
    response[1] = authMethod_;
    
    if (bufferevent_write(inConn_, response, 2) == -1)
    {
        return State::error;
    }

    if (authMethod_ == AUTH_NO_ACCEPTABLE)
    {
        return State::failed;
    }

    return State::success;
}
