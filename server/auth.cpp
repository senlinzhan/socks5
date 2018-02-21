#include "auth.hpp"

#include <vector>

#include <glog/logging.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

Auth::Auth(const Cryptor &cryptor, bufferevent *inConn)
    : cryptor_(cryptor),
      inConn_(inConn),
      authMethod_(AUTH_NO_ACCEPTABLE),
      supportMethods_{AUTH_NONE}
{    
}

Auth::Auth(const Cryptor &cryptor, bufferevent *inConn,
           const std::string &username, const std::string &password)
    : cryptor_(cryptor),
      inConn_(inConn),
      authMethod_(AUTH_NO_ACCEPTABLE),
      supportMethods_{AUTH_USER_PASSWORD},
      username_(username),
      password_(password)
{
}

/**
   Handling client authentication

   Returns:
     State::incomplete        the data received by server is incomplete
     State::success           the authentication is successful
     State::failed            the authentication is failed
     State::error             an error occurred
     State::waitUserPassAuth  wait for username/password authentication

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
    auto data = cryptor_.decryptFrom(inConn_);
    if (data == nullptr)
    {
        return State::error;
    }

    auto size = data->size();
    if (size < 2)
    {
        return State::incomplete;
    }

    // check protocol version number
    if ((*data)[0] != SOCKS5_VERSION)
    {
        return State::error;
    }

    // how many kinds of methods
    unsigned char nmethods = (*data)[1];    
    if (size < 2 + nmethods)
    {
        return State::incomplete;
    }    
    else if (size > 2 + nmethods)
    {
        return State::error;
    }
    cryptor_.removeFrom(inConn_);

    for (int i = 2; i < size; i++)
    {
        auto method = (*data)[i];
        if (supportMethods_.find(method) != supportMethods_.end())
        {
            authMethod_ = method;
            break;
        }        
    }
    
    unsigned char response[2];
    response[0] = SOCKS5_VERSION;
    response[1] = authMethod_;

    if (!cryptor_.encryptTo(inConn_, response, 2))
    {
        return State::error;        
    }    

    if (authMethod_ == AUTH_NO_ACCEPTABLE)
    {
        return State::failed;
    }

    if (authMethod_ == AUTH_USER_PASSWORD)
    {
        return State::waitUserPassAuth;
    }
    
    return State::success;
}


Auth::State Auth::validateUsernamePassword()
{    
    auto data = cryptor_.decryptFrom(inConn_);
    if (data == nullptr)
    {
        return State::error;
    }

    auto size = data->size();
    if (size < 2)
    {
        return State::incomplete;
    }

    // check version number
    if ((*data)[0] != USER_AUTH_VERSION)
    {
        return State::error;
    }

    // get length of username
    auto userLength = (*data)[1];    
    if (size < 3 + userLength)
    {
        return State::incomplete;
    }

    // get length of password
    auto passLength = (*data)[userLength + 2];    
    if (size < 3 + userLength + passLength)
    {
        return State::incomplete;        
    }
    else if (size > 3 + userLength + passLength)
    {
        return State::error;
    }
    cryptor_.removeFrom(inConn_);

    std::string username(&(*data)[2], &(*data)[2 + userLength]);
    std::string password(&(*data)[3 + userLength], &(*data)[size]);

    unsigned char reply[2] = {USER_AUTH_VERSION, USER_AUTH_SUCCESS};
    if (username != username_ || password != password_)
    {
        reply[1] = USER_AUTH_FAILED;

        if (!cryptor_.encryptTo(inConn_, reply, 2))
        {
            return State::error;
        }
        return State::failed;
    }

    if (!cryptor_.encryptTo(inConn_, reply, 2))
    {
        return State::error;
    }
    
    return State::success;
}
