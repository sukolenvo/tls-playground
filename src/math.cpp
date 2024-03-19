#include <stdexcept>

#include "math.hpp"

std::vector<unsigned char> add(const std::vector<unsigned char> &first, const std::vector<unsigned char> &second)
{
	auto result = first;
	if (second.empty())
	{
		return result;
	}
	if (result.size() < second.size())
	{
		result.insert(result.cbegin(), second.size() - result.size(), 0);
	}
	auto resultIterator = result.rbegin();
	auto secondIterator = second.rbegin();
	bool carry = false;
	while (resultIterator != result.rend())
	{
		if (!carry && secondIterator == second.rend()) {
			break;
		}
		int value = *resultIterator + (secondIterator == second.rend() ? 0 : *secondIterator++) + (carry ? 1 : 0);
		*resultIterator = value & 0xFF;
		carry = value > 0xFF;
		++resultIterator;
	}
	if (carry) {
		result.insert(result.cbegin(), 1);
	}
	return result;
}


BigNumber::BigNumber(const std::vector<unsigned char> &state) : state(state)
{

}

BigNumber::BigNumber(std::vector<unsigned char> &&state) : state(state)
{

}

BigNumber operator+(const BigNumber &first, const BigNumber &second)
{
	return BigNumber(add(first.state, second.state));
}

BigNumber operator-(const BigNumber &first, const BigNumber &second)
{
	auto result = first.state;
	if (second.state.empty()) {
		return BigNumber(result);
	}
	auto resultIterator = result.rbegin();
	auto secondIterator = second.state.rbegin();
	bool borrow = false;
	while (resultIterator != result.rend())
	{
		if (!borrow && secondIterator == second.state.rend())
		{
			break;
		}
		int value = *resultIterator - (secondIterator == second.state.rend() ? 0 : *secondIterator++) - (borrow ? 1 : 0);
		if (value < 0) {
			borrow = true;
			value += 0x100;
		} else {
			borrow = false;
		}
		*resultIterator = value;
		++resultIterator;
	}
	if (borrow) {
		throw std::runtime_error("negative result is not supported");
	}
	if (result.front() == 0) {
		auto zeros = result.cbegin();
		while (zeros != result.cend() && *zeros == 0) {
			++zeros;
		}
		result.erase(result.cbegin(), zeros);
	}
	return BigNumber(result);
}

std::ostream& operator << ( std::ostream& os, BigNumber const& value ) {
	os << "BigNumber{";
	for (const auto &item : value.state)
	{
		os << " " << item;
	}
	return os << " }";
}
