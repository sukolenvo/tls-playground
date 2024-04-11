#include <stdexcept>

#include "aes.hpp"

#include "cipher_suite.hpp"

Aes128CipherSuite::Aes128CipherSuite(const std::array<unsigned char, 16> &iv, const std::array<unsigned char, 16> &key)
        : iv(iv), key(key)
{

}

void Aes128CipherSuite::encrypt(TlsRecord &record)
{
    auto padding = 16 - record.payload.size() % 16;
    record.payload.insert(record.payload.end(), padding, padding - 1);
    record.payload = aes128_cbc_encrypt(record.payload, iv, key);
    std::copy(record.payload.end() - iv.size(), record.payload.end(), iv.begin());
}

void Aes128CipherSuite::decrypt(TlsRecord &tls_record)
{
    std::vector<unsigned char> decrypted_block = aes128_cbc_decrypt(tls_record.payload, iv, key);
    if (decrypted_block.empty() || decrypted_block.size() < decrypted_block.back())
    {
        throw std::runtime_error("tls error: malformed payload");
    }
    decrypted_block.resize(decrypted_block.size() - decrypted_block.back() - 1);
    std::copy(tls_record.payload.end() - iv.size(), tls_record.payload.end(), iv.begin());
    tls_record.payload = decrypted_block;
}
