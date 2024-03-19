#ifndef TLS_PLAYGROUND_MATH_HPP
#define TLS_PLAYGROUND_MATH_HPP

#include <vector>

class BigNumber
{
public:
	explicit BigNumber(const std::vector<unsigned char> &state);
	explicit BigNumber(std::vector<unsigned char> &&state);

	friend BigNumber operator+(const BigNumber &first, const BigNumber &second);
	auto operator<=>(const BigNumber &other) const = default;
private:
	std::vector<unsigned char> state;
};


#endif //TLS_PLAYGROUND_MATH_HPP
