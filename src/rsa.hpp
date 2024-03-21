#ifndef TLS_PLAYGROUND_RSA_HPP
#define TLS_PLAYGROUND_RSA_HPP

#include "math.hpp"

BigNumber rsa_compute(const BigNumber &message, const BigNumber &exp, const BigNumber &modulus);

std::vector<unsigned char> rsa_encrypt(const std::vector<unsigned char> &input, const BigNumber &public_key, const BigNumber &modulus);

std::vector<unsigned char> rsa_decrypt(const std::vector<unsigned char> &cypher, const BigNumber &private_key, const BigNumber &modulus);

#endif //TLS_PLAYGROUND_RSA_HPP
