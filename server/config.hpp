/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef CONFIG_H
#define CONFIG_H

#include "address.hpp"

#include <assert.h>

#include <string>
#include <memory>
#include <utility>
 
class Config
{
public:
    using Pair = std::pair<std::string, std::string>;
    
    Config(const std::string &host, unsigned short port,
           const std::string &username, const std::string &password,
           const std::string &key)
        : address_(Address::FromHostOrder(host, port)),          
          userPassAuth_(nullptr),
          key_(key)
    {
        assert(!key_.empty());
        
        if (!username.empty() && !password.empty())
        {
            userPassAuth_ = std::make_shared<Pair>(username, password);
        }
    }

    std::string host() const
    {
        return address_.host();
    }

    std::string portStr() const
    {
        return address_.portString();
    }
    
    unsigned short port() const
    {
        return address_.port();
    }
    
    bool useUserPassAuth() const
    {
        return userPassAuth_ != nullptr;
    }

    std::string username() const
    {
        assert(userPassAuth_ != nullptr);

        return std::get<0>(*userPassAuth_);
    }

    std::string password() const
    {
        assert(userPassAuth_ != nullptr);

        return std::get<1>(*userPassAuth_);        
    }

    std::string key() const
    {
        return key_;
    }
    
    Address address() const
    {
        return address_;
    }
    
private:    
    Address                 address_;
    std::shared_ptr<Pair>   userPassAuth_;
    std::string             key_;
};

#endif /* CONFIG_H */
