find_package (openssl REQUIRED)
find_package (gflags REQUIRED)
include_directories (${gflags_INCLUDE_DIR})
include_directories ("/usr/local/opt/openssl/include" )

find_package (glog REQUIRED)

set(SRCS
    socks5.cpp
    sockets.cpp
    server.cpp
    address.cpp
    tunnel.cpp
    auth.cpp
    request.cpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(socks5 ${SRCS})
target_link_libraries(socks5 event gflags glog::glog ssl)
