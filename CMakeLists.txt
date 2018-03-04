cmake_minimum_required (VERSION 2.8)

project(socks5)

find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

set(SUBDIRS basic local server test thirdparty/gflags thirdparty/glog thirdparty/googletest)
 
foreach(dir ${SUBDIRS})
    add_subdirectory(${dir})
endforeach()

enable_testing()
