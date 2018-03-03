find_package (openssl REQUIRED)

include_directories ("/usr/local/opt/openssl/include" )
include_directories(${PROJECT_SOURCE_DIR}/basic)

find_package (glog REQUIRED)

set(SRCS
    main.cpp
    server.cpp
    tunnel.cpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(local ${SRCS})

link_directories(${PROJECT_BINARY_DIR}/basic)
target_link_libraries(local event gflags glog::glog ssl crypto basic)
