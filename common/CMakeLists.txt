include_directories ("/usr/local/opt/openssl/include")

set(SRCS
    cipher.cpp
    address.cpp
    sockets.cpp)

add_library (common ${SRCS})
