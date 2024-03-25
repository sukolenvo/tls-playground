#ifndef TLS_PLAYGROUND_MATH_HPP
#define TLS_PLAYGROUND_MATH_HPP

#include <ostream>
#include <vector>

enum class Sign
{
	PLUS, MINUS
};

Sign operator~(const Sign &value);

Sign operator^(const Sign &first, const Sign &second);

class BigNumber
{
public:
	explicit BigNumber(const std::vector<unsigned char> &magnitude);

	explicit BigNumber(std::vector<unsigned char> &&magnitude);

	BigNumber(std::vector<unsigned char> &&magnitude, Sign sign);

	BigNumber(const std::vector<unsigned char> &magnitude, Sign sign);

	friend BigNumber operator+(const BigNumber &first, const BigNumber &second);

	friend BigNumber operator-(const BigNumber &first, const BigNumber &second);

	friend BigNumber operator*(const BigNumber &first, const BigNumber &second);

	friend BigNumber operator&(const BigNumber &first, const BigNumber &second);

	friend BigNumber &operator<<=(BigNumber &number, size_t pos);

	friend BigNumber &operator>>=(BigNumber &number, size_t pos);

	friend BigNumber operator%(const BigNumber &first, const BigNumber &second);

	friend BigNumber operator/(const BigNumber &first, const BigNumber &second);

	friend bool operator<(const BigNumber &first, const BigNumber &second);

	friend bool operator<=(const BigNumber &first, const BigNumber &second);

	friend bool operator>(const BigNumber &first, const BigNumber &second);

	bool operator==(const BigNumber &other) const;

	friend std::ostream &operator<<(std::ostream &os, BigNumber const &value);

	[[nodiscard]]
	BigNumber power_modulus(const BigNumber &exp, const BigNumber &modulus) const;

	[[nodiscard]]
	BigNumber inverse_multiplicative(const BigNumber &modulus) const;

	[[nodiscard]]
	size_t bit_length() const;

	[[nodiscard]]
	std::vector<unsigned char> data() const;

private:
	std::vector<unsigned char> magnitude;
	Sign sign;
};

const BigNumber ZERO = BigNumber({});

#endif //TLS_PLAYGROUND_MATH_HPP
