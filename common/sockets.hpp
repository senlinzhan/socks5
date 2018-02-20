/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#ifndef SOCKETS_H
#define SOCKETS_H

#include "address.hpp"

#include <string>
#include <arpa/inet.h>

/**
    Create the listening socket and make it nonblocking
    Returns the listening socket descriptor on success, -1 on failure
 **/
int createListeningSocket(const char *hostname, const char *service);
int createListeningSocket(const std::string &hostname, const std::string &service);

Address getSocketLocalAddress(int fd);

#endif /* SOCKETS_H */
