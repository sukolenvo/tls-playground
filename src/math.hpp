#ifndef TLS_PLAYGROUND_MATH_HPP
#define TLS_PLAYGROUND_MATH_HPP

#include <ostream>
#include <vector>

enum class Sign
{
	PLUS, MINUS
};

Sign operator~(const Sign &value);

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
	friend BigNumber& operator<<=(BigNumber &number, size_t pos);
	friend BigNumber& operator>>=(BigNumber &number, size_t pos);
	friend BigNumber operator%(const BigNumber &first, const BigNumber &second);
	friend bool operator<(const BigNumber &first, const BigNumber &second);
	friend bool operator>(const BigNumber &first, const BigNumber &second);
	bool operator==(const BigNumber &other) const;
	friend std::ostream& operator << ( std::ostream& os, BigNumber const& value );

	[[ nodiscard ]] size_t bit_length() const;
	std::vector<unsigned char> data();
private:
	std::vector<unsigned char> magnitude;
	Sign sign;
};

const BigNumber ZERO = BigNumber({});

#endif //TLS_PLAYGROUND_MATH_HPP
