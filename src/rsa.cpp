#include "rsa.hpp"

BigNumber rsa_compute(const BigNumber &message, const BigNumber &exp, const BigNumber &modulus)
{
	BigNumber result({1});
	BigNumber multiplier = message;
	BigNumber mask({1});
	while (mask < exp)
	{
		if ((mask & exp) != ZERO)
		{
			result = result * multiplier % modulus;
		}
		mask <<= 1;
		multiplier = multiplier * multiplier % modulus;
	}
	return result;
}
