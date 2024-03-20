#ifndef TLS_PLAYGROUND_RSA_HPP
#define TLS_PLAYGROUND_RSA_HPP

#include "math.hpp"

BigNumber rsa_compute(const BigNumber &message, const BigNumber &exp, const BigNumber &modulus);

#endif //TLS_PLAYGROUND_RSA_HPP
