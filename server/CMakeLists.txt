set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wunused-variable -Werror")

include_directories(${PROJECT_SOURCE_DIR}/basic)

set(SRCS
    socks5.cpp
    server.cpp
    tunnel.cpp
    auth.cpp
    request.cpp
)

add_executable(socks5 ${SRCS})

link_directories(${PROJECT_BINARY_DIR}/basic)
target_link_libraries(socks5 event gflags glog::glog basic)
