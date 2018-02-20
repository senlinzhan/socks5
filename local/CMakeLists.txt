find_package (openssl REQUIRED)
find_package (gflags REQUIRED)

include_directories (${gflags_INCLUDE_DIR})
include_directories ("/usr/local/opt/openssl/include" )
include_directories(${PROJECT_SOURCE_DIR}/basic)

find_package (glog REQUIRED)

set(SRCS
    main.cpp
    local.cpp
    conn.cpp
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(local ${SRCS})

link_directories(${PROJECT_BINARY_DIR}/basic)
target_link_libraries(local event gflags glog::glog ssl crypto basic)
