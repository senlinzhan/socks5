cmake_minimum_required (VERSION 2.8)

project(socks4a)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wunused-variable -Werror")

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

set(SUBDIRS server basic local test)
 
foreach(dir ${SUBDIRS})
    add_subdirectory(${dir})
endforeach()

enable_testing()
