enable_testing()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -Wall -Wunused-variable -Werror")

include_directories(${PROJECT_SOURCE_DIR}/basic)

add_executable(cipher_test cipher_test.cpp)

target_link_libraries(cipher_test ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(cipher_test basic event glog::glog gtest)

add_test(Test cipher_test)
