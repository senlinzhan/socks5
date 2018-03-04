cmake_minimum_required (VERSION 2.8)

project(socks5)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_subdirectory(thirdparty/gflags)
add_subdirectory(thirdparty/glog)
add_subdirectory(thirdparty/googletest)
add_subdirectory(thirdparty/libevent)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(SUBDIRS basic local server test)
 
foreach(dir ${SUBDIRS})
    add_subdirectory(${dir})
endforeach()

enable_testing()
