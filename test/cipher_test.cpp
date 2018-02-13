#include "cipher.hpp"
#include <gtest/gtest.h>

Cryptor::Key key
{{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
}};

Cryptor::IV iv
{{
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
}};

class CipherTest : public testing::Test
{
protected:    
    CipherTest()
        : cryptor_(key, iv)
    {
    }

    Cryptor cryptor_;
};

TEST_F(CipherTest, EncryptAndDecrypt)
{
    auto text = "Hello, World!";
    auto length = strlen(text);
    
    auto bytes = reinterpret_cast<const Cryptor::Byte*>(text);
    auto encrypted = cryptor_.encrypt(bytes, length);
    
    EXPECT_NE(encrypted, nullptr);
    EXPECT_GE(encrypted->size(), length);

    auto decrypted = cryptor_.decrypt(encrypted->data(), encrypted->size());
    EXPECT_NE(decrypted, nullptr);
    EXPECT_EQ(decrypted->size(), length);

    Cryptor::Buffer buffer(text, text + length);
    EXPECT_EQ(*decrypted, buffer);
}

int main(int argc, char **argv)
{
    ::testing::InitGoogleTest(&argc, argv);

    int ret = RUN_ALL_TESTS();
    return ret;
}
