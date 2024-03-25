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
	BigNumber a, b;

	[[nodiscard]]
	BigPoint sum_points(const BigPoint &first, const BigPoint &second, const BigNumber &modulus) const;

	[[nodiscard]]
	BigPoint double_point(const BigPoint &point, const BigNumber &modulus) const;

public:
	EllipticCurve(BigNumber a, BigNumber b);

	[[nodiscard]]
	BigPoint multiply_point(const BigPoint &point, const BigNumber &multiplier, const BigNumber &modulus) const;
};

#endif //TLS_PLAYGROUND_ECC_HPP
