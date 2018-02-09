#ifndef CONFIG_H
#define CONFIG_H

#include <assert.h>

#include <string>
#include <memory>
#include <utility>
 
class Config
{
public:
    using Pair = std::pair<std::string, std::string>;
    
    Config(const std::string &host, unsigned short port,
           const std::string &username, const std::string &password)
        : host_(host),
          port_(port),
          userPassAuth_(nullptr)
    {
        assert(!host_.empty());

        if (!username.empty() && !password.empty())
        {
            userPassAuth_ = std::make_shared<Pair>(username, password);
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
    
private:    
    std::string             host_;
    unsigned short          port_;
    std::shared_ptr<Pair>   userPassAuth_;
};

#endif /* CONFIG_H */
