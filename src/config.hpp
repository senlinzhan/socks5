#ifndef CONFIG_H
#define CONFIG_H

#include <assert.h>

#include <string>
#include <memory>
#include <utility>
 
class Config
{
public:
    enum class Mode { client, server };

    using Pair = std::pair<std::string, std::string>;
    
    Config(const std::string &host, unsigned short port,
           const std::string &username, const std::string &password,
           const std::string &key, const std::string &mode)
        : host_(host),
          port_(port),
          userPassAuth_(nullptr),
          key_(key)
    {
        assert(!host_.empty());
        assert(!key_.empty());
        
        assert(mode == "client" || mode == "server");
        
        if (!username.empty() && !password.empty())
        {
            userPassAuth_ = std::make_shared<Pair>(username, password);
        }
        
        if (mode == "client")
        {
            mode_ = Mode::client;
        }
        else
        {
            mode_ = Mode::server;
        }
    }

    std::string host() const
    {
        return host_;
    }

    unsigned short port() const
    {
        return port_;
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

    Mode mode() const
    {
        return mode_;
    }
    
private:    
    std::string             host_;
    unsigned short          port_;
    std::shared_ptr<Pair>   userPassAuth_;
    std::string             key_;
    Mode                    mode_;
};

#endif /* CONFIG_H */
