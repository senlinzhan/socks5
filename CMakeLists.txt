cmake_minimum_required (VERSION 2.8)

project(socks5)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -Wall -Wsign-compare -Wignored-qualifiers -std=c++11 -pthread")

include(ExternalProject)

# Build googletest as an external project.
set(GTEST_INSTALL_DIR ${CMAKE_BINARY_DIR}/thirdparty/googletest)
set(GTEST_INCLUDE_DIR ${GTEST_INSTALL_DIR}/include)
set(GTEST_LIB_DIR ${GTEST_INSTALL_DIR}/lib)
ExternalProject_Add(gtest_external_project
                    SOURCE_DIR  ${CMAKE_SOURCE_DIR}/thirdparty/googletest
                    PREFIX      ${GTEST_INSTALL_DIR}
                    INSTALL_DIR ${GTEST_INSTALL_DIR}
                    CMAKE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=${GTEST_INSTALL_DIR}
                                -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                                -DCMAKE_CXX_FLAGS=${EXTERNAL_PROJECT_CMAKE_CXX_FLAGS}
                   )
include_directories(BEFORE SYSTEM ${GTEST_INCLUDE_DIR})
link_directories(${GTEST_LIB_DIR})

# Build gflags as an external project.
set(GFLAGS_INSTALL_DIR ${CMAKE_BINARY_DIR}/thirdparty/gflags)
set(GFLAGS_INCLUDE_DIR ${GFLAGS_INSTALL_DIR}/include)
set(GFLAGS_LIB_DIR ${GFLAGS_INSTALL_DIR}/lib)
ExternalProject_Add(gflags_external_project
                    SOURCE_DIR  ${CMAKE_SOURCE_DIR}/thirdparty/gflags
                    PREFIX      ${GFLAGS_INSTALL_DIR}
                    INSTALL_DIR ${GFLAGS_INSTALL_DIR}
                    CMAKE_ARGS  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                                -DCMAKE_CXX_FLAGS=${EXTERNAL_PROJECT_CMAKE_CXX_FLAGS}
                                -DCMAKE_INSTALL_PREFIX:PATH=${GFLAGS_INSTALL_DIR}
                   )
include_directories(BEFORE SYSTEM ${GFLAGS_INCLUDE_DIR})
link_directories(${GFLAGS_LIB_DIR})

# Build glog as an external project.
set(GLOG_INSTALL_DIR ${CMAKE_BINARY_DIR}/thirdparty/glog)
set(GLOG_INCLUDE_DIR ${GLOG_INSTALL_DIR}/include)
set(GLOG_LIB_DIR ${GLOG_INSTALL_DIR}/lib)
ExternalProject_Add(glog_external_project
                    SOURCE_DIR  ${CMAKE_SOURCE_DIR}/thirdparty/glog
                    PREFIX      ${GLOG_INSTALL_DIR}
                    INSTALL_DIR ${GLOG_INSTALL_DIR}
                    CMAKE_ARGS  -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
                                -DCMAKE_CXX_FLAGS=${EXTERNAL_PROJECT_CMAKE_CXX_FLAGS}
                                -Dgflags_DIR=${GFLAGS_INSTALL_DIR}
                                -DCMAKE_INSTALL_PREFIX:PATH=${GLOG_INSTALL_DIR}
                    DEPENDS     gflags_external_project
                   )
include_directories(BEFORE SYSTEM ${GLOG_INCLUDE_DIR})
link_directories(${GLOG_LIB_DIR})


set(SUBDIRS basic local server test)
 
foreach(dir ${SUBDIRS})
    add_subdirectory(${dir})
endforeach()

enable_testing()
