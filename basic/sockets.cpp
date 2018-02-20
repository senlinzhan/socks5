/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "sockets.hpp"

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>

#include <event2/util.h>

int createListeningSocket(const char *hostname, const char *service)
{
    struct addrinfo hints;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    struct addrinfo *servinfo;
    int status = getaddrinfo(hostname, service, &hints, &servinfo);
    if(status != 0)
    {
        return -1;
    }

    int sockfd;
    struct addrinfo *ptr;
    for(ptr = servinfo; ptr != nullptr; ptr = ptr->ai_next)
    {
        sockfd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sockfd != -1)
        {
            if (evutil_make_socket_nonblocking(sockfd) == 0
                && ::bind(sockfd, ptr->ai_addr, ptr->ai_addrlen) == 0)
            {
                break;
            }
            
            ::close(sockfd);
            sockfd = -1;
        }        
    }
    
    freeaddrinfo(servinfo);
    
    return sockfd;    
}

int createListeningSocket(const std::string &hostname, const std::string &service)
{
    return createListeningSocket(hostname.c_str(), service.c_str());
}

Address getSocketLocalAddress(int fd)
{
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);    
    
    memset(&addr, 0, len);
    if (::getsockname(fd, reinterpret_cast<struct sockaddr *>(&addr), &len) < 0)
    {
        return Address();
    }

    return Address(reinterpret_cast<struct sockaddr *>(&addr));
}
