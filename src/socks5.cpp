/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2017 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

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


int main(int argc, char *argv[])
{
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

    LOG(WARNING) << "socks5 options: "
                 << "Listening host = " << FLAGS_host << ", "
                 << "Listening port = " << FLAGS_port;

    Server server(FLAGS_host, FLAGS_port);
    server.run();
    
    return 0;
}
