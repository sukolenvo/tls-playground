#ifndef TLS_PLAYGROUND_ECC_HPP
#define TLS_PLAYGROUND_ECC_HPP

#include "math.hpp"

struct BigPoint
{
    BigNumber x;
    BigNumber y;

    friend bool operator==(const BigPoint &first, const BigPoint &second);
};


class EllipticCurve
{
    BigNumber a, b, modulus;

    [[nodiscard]]
    BigPoint double_point(const BigPoint &point) const;

public:
    EllipticCurve(BigNumber a, BigNumber b, BigNumber modulus);

    [[nodiscard]]
    BigPoint sum_points(const BigPoint &first, const BigPoint &second) const;

    [[nodiscard]]
    BigPoint multiply_point(const BigPoint &point, const BigNumber &multiplier) const;
};

#endif //TLS_PLAYGROUND_ECC_HPP
