#ifndef CIPHER_H
#define CIPHER_H

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
    static constexpr int LEN_BYTES   = 4;
    
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

    Cryptor(const std::string &key, const std::string &iv);

    /**
       Encrypt data - return the encrypted data on success, nullptr on failed
     **/
    BufferPtr encrypt(const Byte *in, std::size_t inLength) const;

    /**
       Decrypt data - return the decrypted data on success, nullptr on failed
     **/    
    BufferPtr decrypt(const Byte *in, std::size_t inLength) const;

    /**
       Decrypt data and transfer data from inConn to outConn,
       return true on success, false on failed
     **/
    bool decryptTransfer(bufferevent *inConn, bufferevent *outConn) const;

    /**
       Encrypt data and transfer data from inConn to outConn,
       return true on success, false on failed
     **/
    bool encryptTransfer(bufferevent *inConn, bufferevent *outConn) const;

    /**
       Read data from conn and decrypt the data,
       return the data on success, nullptr on failed       
     **/
    BufferPtr decryptFrom(bufferevent *conn) const;

    /**
       Encrypt data and send the data to conn,
       return true on success, nullptr on failed
     **/
    bool encryptTo(bufferevent *conn, const Byte *in, std::size_t inLength) const;
    
    /**
       Read data from conn and return the data 
     **/
    Buffer readFrom(bufferevent *conn) const;

    /**
       Remove data from conn and return the data
     **/
    void removeFrom(bufferevent *conn) const;
    
private:
    int lengthOfEncryptedData(const Buffer &buff) const;

    int lengthOfInput(bufferevent *inConn) const
    {
        auto inBuff = bufferevent_get_input(inConn);
        return evbuffer_get_length(inBuff);    
    }
    
    Key  key_;
    IV   iv_;
};

#endif /* CIPHER_H */
