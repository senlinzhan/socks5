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

#include <string>
#include <arpa/inet.h>

int createListeningSocket(const char *hostname, const char *service);

#endif /* SOCKETS_H */
