#ifndef TLS_PLAYGROUND_MATH_HPP
#define TLS_PLAYGROUND_MATH_HPP

#include <ostream>
#include <vector>

class BigNumber
{
public:
	explicit BigNumber(const std::vector<unsigned char> &state);
	explicit BigNumber(std::vector<unsigned char> &&state);

	friend BigNumber operator+(const BigNumber &first, const BigNumber &second);
	friend BigNumber operator-(const BigNumber &first, const BigNumber &second);
	friend BigNumber operator*(const BigNumber &first, const BigNumber &second);
	friend BigNumber& operator<<=(BigNumber &number, size_t pos);
	friend BigNumber& operator>>=(BigNumber &number, size_t pos);
	friend BigNumber operator%(const BigNumber &first, const BigNumber &second);
	friend bool operator<(const BigNumber &first, const BigNumber &second);
	friend bool operator>(const BigNumber &first, const BigNumber &second);
	bool operator==(const BigNumber &other) const = default;
	friend std::ostream& operator << ( std::ostream& os, BigNumber const& value );
private:
	std::vector<unsigned char> state;
};

#endif //TLS_PLAYGROUND_MATH_HPP
