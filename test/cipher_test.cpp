#include "cipher.hpp"
#include <gtest/gtest.h>

class CipherTest : public testing::Test
{
protected:    
    CipherTest()
        : cryptor_(Cryptor::Key(), Cryptor::IV{})
    {
    }

    Cryptor cryptor_;
};


int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    int ret = RUN_ALL_TESTS();
    return ret;
}
