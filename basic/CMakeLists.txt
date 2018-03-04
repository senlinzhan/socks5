set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wunused-variable -Werror")

set(SRCS
    base.cpp
    cipher.cpp
    address.cpp
    sockets.cpp)

add_library (basic ${SRCS})
target_link_libraries(basic ssl crypto)
