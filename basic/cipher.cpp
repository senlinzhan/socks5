#include <iostream>

#include "cipher.hpp"

Cryptor::Cryptor(const std::string &key, const std::string &iv)
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

Cryptor::BufferPtr Cryptor::encrypt(const Byte *in, std::size_t inLength) const
{
    ContextPtr ctx(EVP_CIPHER_CTX_new(), contextDeleter);
    if (ctx == nullptr)
    {
        return nullptr;
    }

    if(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                          key_.data(), iv_.data()) != 1)
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

Cryptor::BufferPtr Cryptor::decrypt(const Byte *in, std::size_t inLength) const
{
    ContextPtr ctx(EVP_CIPHER_CTX_new(), contextDeleter);
    if (ctx == nullptr)
    {
        return nullptr;
    }
        
    if(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr,
                          key_.data(), iv_.data()) != 1)
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

bool Cryptor::decryptTransfer(bufferevent *inConn, bufferevent *outConn) const
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    auto decrypted = decryptFrom(inConn);
    if (decrypted == nullptr)
    {
        return false;
    }

    for (auto c: *decrypted)
    {
        std::cerr << c << std::endl;
    }
    
    if (bufferevent_write(outConn, decrypted->data(), decrypted->size()) == -1)
    {
        return false;
    }
    
    return true;    
}

bool Cryptor::encryptTransfer(bufferevent *inConn, bufferevent *outConn) const
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    auto buff = removeFrom(inConn);
    return encryptTo(outConn, buff.data(), buff.size());
}

Cryptor::BufferPtr Cryptor::decryptFrom(bufferevent *conn) const
{
    auto buff = readFrom(conn);    
    return decrypt(buff.data(), buff.size());
}

bool Cryptor::encryptTo(bufferevent *conn, const Byte *in, std::size_t inLength) const
{
    assert(conn != nullptr);

    auto encrypted = encrypt(in, inLength);
    if (encrypted == nullptr)
    {
        return false;
    }

    if (bufferevent_write(conn, encrypted->data(), encrypted->size()) == -1)
    {
        return false;
    }
    
    return true;
}

Cryptor::Buffer Cryptor::readFrom(bufferevent *conn) const
{
    assert(conn != nullptr);

    auto inBuff = bufferevent_get_input(conn);
    auto inBuffLength = evbuffer_get_length(inBuff);

    std::vector<unsigned char> buff(inBuffLength, 0);
    evbuffer_copyout(inBuff, buff.data(), buff.size());

    return buff;
}

Cryptor::Buffer Cryptor::removeFrom(bufferevent *conn) const
{
    assert(conn != nullptr);

    auto inBuff = bufferevent_get_input(conn);
    auto inBuffLength = evbuffer_get_length(inBuff);

    std::vector<unsigned char> buff(inBuffLength, 0);
    evbuffer_remove(inBuff, buff.data(), buff.size());

    return buff;
}
