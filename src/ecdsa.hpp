#ifndef TLS_PLAYGROUND_ECDSA_HPP
#define TLS_PLAYGROUND_ECDSA_HPP

#include "ecc.hpp"
#include "dsa.hpp"

class EcDsa
{
    BigNumber q, k;
    BigPoint generator;
    EllipticCurve curve;

public:
    EcDsa(BigNumber q, BigPoint generator, EllipticCurve curve);

    EcDsa(BigNumber q, BigNumber k, BigPoint generator, EllipticCurve curve);

    [[nodiscard]]
    DsaSignature sign(const std::vector<unsigned char> &message, const BigNumber &private_key) const;

    [[nodiscard]]
    bool verify(
            const std::vector<unsigned char> &message,
            const DsaSignature &signature,
            const BigPoint &public_key) const;
};

#endif //TLS_PLAYGROUND_ECDSA_HPP
