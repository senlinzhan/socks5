/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "config.hpp"
#include "server.hpp"

#include <gflags/gflags.h>
#include <glog/logging.h>

// check whether the port is in range [1, 65535]
static bool isValidPort(const char* flagname, gflags::int32 value)
{
    return (value > 0 && value < 65536);
}

DEFINE_string(host, "localhost", "Listening host");

DEFINE_int32(port, 6060, "Listening port");
DEFINE_validator(port, &isValidPort);

DEFINE_string(username, "", "Username for login");
DEFINE_string(password, "", "password for login");


int main(int argc, char *argv[])
{ 
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

    Config config(
        FLAGS_host, static_cast<unsigned short>(FLAGS_port),
        FLAGS_username, FLAGS_password
    );    
    
    LOG(WARNING) << "Socks5 options: "
                 << "Listening host = " << config.host() << ", "
                 << "Listening port = " << config.port();

    if (config.useUserPassAuth())
    {
        LOG(WARNING) << "Enable Username/Password authentication: "
                     << "username = " << config.username()
                     << ", password = " << config.password();
    }

    Server server(config);
    server.run();
    
    return 0;
}
