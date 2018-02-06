#ifndef AUTH_H
#define AUTH_H

#include <unordered_set>

/**
   Forward declaration
 **/
struct bufferevent;

class Auth
{
public:
    enum class State { incomplete, success, failed, error };
    
    Auth(bufferevent *inConn);
    
    // disable the copy operations    
    Auth(const Auth &) = delete;
    Auth &operator=(const Auth &) = delete;

    State authenticate();
    
private:
    static constexpr unsigned char      SOCKS5_VERSION          = 0x05;    
    static constexpr unsigned char      AUTH_NONE               = 0x00;
    static constexpr unsigned char      AUTH_USER_PASSWORD      = 0x02;        
    static constexpr unsigned char      AUTH_NO_ACCEPTABLE      = 0xFF;
    
    bufferevent                         *inConn_;
    unsigned char                       authMethod_;
    std::unordered_set<unsigned char>   supportMethods_;
};

#endif /* AUTH_H */
