include_directories ("/usr/local/opt/openssl/include")

set(SRCS
    base.cpp
    cipher.cpp
    address.cpp
    sockets.cpp)

add_library (basic ${SRCS})
