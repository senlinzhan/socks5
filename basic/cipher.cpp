#include "cipher.hpp"

bool decryptTransfer(const Cryptor &cryptor, bufferevent *inConn, bufferevent *outConn)
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    auto inBuff = bufferevent_get_input(inConn);
    auto inBuffLength = evbuffer_get_length(inBuff);

    std::vector<unsigned char> buff(inBuffLength, 0);
    if (evbuffer_remove(inBuff, buff.data(), buff.size()) == -1)
    {
        return false;
    }

    auto encrypted = cryptor.decrypt(buff.data(), buff.size());
    if (encrypted == nullptr)
    {
        return false;
    }

    if (bufferevent_write(outConn, encrypted->data(), encrypted->size()) == -1)
    {
        return false;
    }
    
    return true;    
}

bool encryptTransfer(const Cryptor &cryptor, bufferevent *inConn, bufferevent *outConn)
{
    assert(inConn != nullptr);
    assert(outConn != nullptr);

    auto inBuff = bufferevent_get_input(inConn);
    auto inBuffLength = evbuffer_get_length(inBuff);

    std::vector<unsigned char> buff(inBuffLength, 0);
    if (evbuffer_remove(inBuff, buff.data(), buff.size()) == -1)
    {
        return false;
    }

    auto encrypted = cryptor.encrypt(buff.data(), buff.size());
    if (encrypted == nullptr)
    {
        return false;
    }

    if (bufferevent_write(outConn, encrypted->data(), encrypted->size()) == -1)
    {
        return false;
    }
    
    return true;
}
