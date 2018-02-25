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

    int length1 = inLength + BLOCK_SIZE;                
    auto result = BufferPtr(new Buffer(length1, 0));

    if(EVP_EncryptUpdate(ctx.get(), result->data(), &length1, in, inLength) != 1)
    {
        return nullptr;
    }

    int length2 = result->size() - length1;
    if(EVP_EncryptFinal_ex(ctx.get(), result->data() + length1, &length2) != 1)
    {
        return nullptr;
    }
    
    result->resize(length1 + length2);

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

    int length1 = inLength;    
    auto result = BufferPtr(new Buffer(length1, 0));

    if(EVP_DecryptUpdate(ctx.get(), result->data(), &length1, in, inLength) != 1)
    {
        return nullptr;
    }    

    int length2 = result->size() - length1;    
    if(EVP_DecryptFinal_ex(ctx.get(), result->data() + length1, &length2) != 1)
    {
        return nullptr;
    }

    result->resize(length1 + length2);

    return result;    
}

int Cryptor::lengthOfEncryptedData(const Buffer &buff) const
{
    int length = 0;
    
    std::copy(buff.begin(), buff.begin() + 4,
              reinterpret_cast<unsigned char *>(&length));

    return ntohl(length);
}

Cryptor::BufferPtr Cryptor::decryptFrom(bufferevent *inConn) const
{
    assert(inConn != nullptr);
    
    int inBuffLength = lengthOfInput(inConn);
    if (inBuffLength <= LEN_BYTES)
    {
        return nullptr;
    }

    auto buff = readFrom(inConn);
    int length = lengthOfEncryptedData(buff);
    if (inBuffLength < length + LEN_BYTES)
    {
        return nullptr;
    }

    return decrypt(buff.data() + 4, length);
}

bool Cryptor::decryptTransfer(bufferevent *inConn, bufferevent *outConn) const
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    int inBuffLength = lengthOfInput(inConn);
    if (inBuffLength <= LEN_BYTES)
    {
        return false;
    }

    auto buff = readFrom(inConn);
    int length = lengthOfEncryptedData(buff);
    if (inBuffLength < length + LEN_BYTES)
    {
        return false;
    }

    auto decrypted = decrypt(buff.data() + LEN_BYTES, length);
    if (decrypted == nullptr)
    {
        return false;
    }
    
    if (bufferevent_write(outConn, decrypted->data(), decrypted->size()) == -1)
    {
        return false;
    }

    evbuffer_drain(bufferevent_get_input(inConn), length + LEN_BYTES);
    
    return true;    
}

bool Cryptor::encryptTransfer(bufferevent *inConn, bufferevent *outConn) const
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    auto buff = readFrom(inConn);
    if (!encryptTo(outConn, buff.data(), buff.size()))
    {
        return false;
    }

    evbuffer_drain(bufferevent_get_input(inConn), buff.size());

    return true;
}


bool Cryptor::encryptTo(bufferevent *outConn, const Byte *in, std::size_t inLength) const
{
    assert(outConn != nullptr);

    auto encrypted = encrypt(in, inLength);
    if (encrypted == nullptr)
    {
        return false;
    }

    int size = encrypted->size();
    int sizeNetwork = htonl(size);
    
    bufferevent_write(outConn, reinterpret_cast<unsigned char *>(&sizeNetwork),
                      LEN_BYTES);
    
    if (bufferevent_write(outConn, encrypted->data(), encrypted->size()) == -1)
    {
        return false;
    }
    
    return true;
}


Cryptor::Buffer Cryptor::readFrom(bufferevent *inConn) const
{
    assert(inConn != nullptr);
    
    auto inBuff = bufferevent_get_input(inConn);
    auto inBuffLength = evbuffer_get_length(inBuff);

    std::vector<unsigned char> buff(inBuffLength, 0);
    evbuffer_copyout(inBuff, buff.data(), buff.size());

    return buff;
}

void Cryptor::removeFrom(bufferevent *inConn) const
{
    assert(inConn != nullptr);
    
    int inBuffLength = lengthOfInput(inConn);
    if (inBuffLength <= LEN_BYTES)
    {
        return;
    }

    auto buff = readFrom(inConn);
    int length = lengthOfEncryptedData(buff);
    if (inBuffLength < length + LEN_BYTES)
    {
        return;
    }

    evbuffer_drain(bufferevent_get_input(inConn), length + LEN_BYTES);
}
