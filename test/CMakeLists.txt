enable_testing()

find_package (openssl REQUIRED)
find_package (gflags REQUIRED)

include_directories(${GTEST_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/src)
include_directories ("/usr/local/opt/openssl/include" )
include_directories (${gflags_INCLUDE_DIR})

add_executable(cipher_test cipher_test.cpp)

target_link_libraries(cipher_test ${GTEST_BOTH_LIBRARIES})

add_test(Test cipher_test)
