/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "local.hpp"

int main(int argc, char *argv[])
{
    Local local("127.0.0.1", 4500, "localhost", 6060, "12345678123456781234567812345678");
    local.run();
    
    return 0;
}
