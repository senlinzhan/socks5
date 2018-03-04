set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wunused-variable -Werror")

include_directories(${PROJECT_SOURCE_DIR}/basic)

set(SRCS
    main.cpp
    server.cpp
    tunnel.cpp
)

add_executable(local ${SRCS})

link_directories(${PROJECT_BINARY_DIR}/basic)
target_link_libraries(local event gflags gtest glog basic)
