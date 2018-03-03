/*******************************************************************************
 *
 * socks5
 * A C++11 socks5 proxy server based on Libevent 
 *
 * Copyright 2018 Senlin Zhan. All rights reserved.
 *
 ******************************************************************************/

#include "cipher.hpp"
#include "config.hpp"
#include "server.hpp"

#include <gflags/gflags.h>
#include <glog/logging.h>

// Check whether the port is in range [1, 65535]
static bool isValidPort(const char* flagname, gflags::int32 value)
{
    return (value > 0 && value < 65536);
}

// Check whether the screct key is valid
static bool isValidSecretKey(const char *flagname, const std::string &value)
{
    return value.size() == Cryptor::KEY_SIZE;
}

// Listening address of the proxy server
DEFINE_string(host, "0.0.0.0", "Listening host");
DEFINE_int32(port, 6060, "Listening port");
DEFINE_validator(port, &isValidPort);

// Username and password for authentication
DEFINE_string(username, "", "Username for login <optional>");
DEFINE_string(password, "", "Password for login <optional>");

// Secret key
DEFINE_string(key, "12345678123456781234567812345678", "Secret key");
DEFINE_validator(key, &isValidSecretKey);

int main(int argc, char *argv[])
{ 
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    google::InitGoogleLogging(argv[0]);

    Config config(
        FLAGS_host, static_cast<unsigned short>(FLAGS_port),
        FLAGS_username, FLAGS_password, FLAGS_key
    );     
    
    LOG(WARNING) << "Socks5 options: "
                 << "Listening host = " << config.host() << ", "
                 << "Listening port = " << config.port() << ", "
                 << "Secret key = " << config.key();

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
