#ifndef CIPHER_H
#define CIPHER_H

#include <assert.h>

#include <array>
#include <memory>
#include <vector>
#include <functional>
#include <string>

#include <openssl/conf.h>
#include <openssl/evp.h>

#include <event2/buffer.h>
#include <event2/bufferevent.h>

class Cryptor
{
public:
    static constexpr int KEY_SIZE    = 32;
    static constexpr int BLOCK_SIZE  = 16;

    static void contextDeleter(EVP_CIPHER_CTX *ctx)
    {
        EVP_CIPHER_CTX_free(ctx);
    }

    using Byte         = unsigned char;
    using Buffer       = std::vector<Byte>;
    using BufferPtr    = std::unique_ptr<Buffer>;
    
    using Key          = std::array<Byte, KEY_SIZE>;
    using IV           = std::array<Byte, BLOCK_SIZE>;
    using ContextPtr   = std::unique_ptr<EVP_CIPHER_CTX, std::function<void (EVP_CIPHER_CTX *)>>; 
    
    Cryptor(const Key &key, const IV &iv)        
        : key_(key),
          iv_(iv)
    {        
    }

    Cryptor(const std::string &key, const std::string &iv)
    {
        assert(key.size() == KEY_SIZE);
        assert(iv.size() == BLOCK_SIZE);

        for (int i = 0; i < KEY_SIZE; i++)
        {
            key_[i] = static_cast<Byte>(key[i]);            
        }

        for (int i = 0; i < BLOCK_SIZE; i++)
        {
            iv_[i] = static_cast<Byte>(iv[i]);
        }        
    }
    
    BufferPtr encrypt(const Byte *in, std::size_t inLength) const
    {
        ContextPtr ctx(EVP_CIPHER_CTX_new(), contextDeleter);
        if (ctx == nullptr)
        {
            return nullptr;
        }

        if(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1)
        {
            return nullptr;
        }

        int length = 0;                
        auto result = BufferPtr(new Buffer(inLength + BLOCK_SIZE, 0));

        if(EVP_EncryptUpdate(ctx.get(), result->data(), &length, in, inLength) != 1)
        {
            return nullptr;
        }
        
        int outLength = length;        
        if(EVP_EncryptFinal_ex(ctx.get(), result->data() + length, &length) != 1)
        {
            return nullptr;
        }
        
        outLength += length;
        result->resize(outLength);

        return result;
    }
    
    BufferPtr decrypt(const Byte *in, std::size_t inLength) const
    {
        ContextPtr ctx(EVP_CIPHER_CTX_new(), contextDeleter);
        if (ctx == nullptr)
        {
            return nullptr;
        }
        
        if(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data()) != 1)
        {
            return nullptr;
        }

        int length = 0;        
        auto result = BufferPtr(new Buffer(inLength, 0));
        
        if(EVP_DecryptUpdate(ctx.get(), result->data(), &length, in, inLength) != 1)
        {
            return nullptr;
        }
        
        int outLength = length;
        if(EVP_DecryptFinal_ex(ctx.get(), result->data() + length, &length) != 1)
        {
            return nullptr;
        }
        
        outLength += length;
        result->resize(outLength);

        return result;
    }
    
private:
    Key  key_;
    IV   iv_;
};

bool decryptTransfer(const Cryptor &cryptor, bufferevent *inConn, bufferevent *outConn);


bool encryptTransfer(const Cryptor &cryptor, bufferevent *inConn, bufferevent *outConn);

#endif /* CIPHER_H */
