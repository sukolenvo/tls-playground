#include <algorithm>
#include <stdexcept>
#include <ranges>

#include "math.hpp"

using Magnitude = std::vector<unsigned char>;

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


BigNumber::BigNumber(const std::vector<unsigned char> &state) : magnitude(state), sign(Sign::PLUS)
{

}

BigNumber::BigNumber(std::vector<unsigned char> &&state) : magnitude(state), sign(Sign::PLUS)
{

}

BigNumber::BigNumber(std::vector<unsigned char> &&state, Sign sign) : magnitude(state), sign(sign)
{

}

int compare_magnitudes(const Magnitude &first, const Magnitude &second)
{
	if (first.size() != second.size()) {
		return first.size() < second.size() ? - 1 : 1;
	}
	for (size_t i = 0; i < first.size(); ++i)
	{
		if (first.at(i) != second.at(i))
		{
			return first.at(i) < second.at(i) ? -1 : 1;
		}
	}
	return 0;
}

void remove_trailing_zeros(Magnitude &magnitude)
{
	if (magnitude.empty())
	{
		return;
	}
	if (magnitude.front() == 0) {
		auto zeros = magnitude.cbegin();
		while (zeros != magnitude.cend() && *zeros == 0) {
			++zeros;
		}
		magnitude.erase(magnitude.cbegin(), zeros);
	}
}

Magnitude subtract_magnitudes(const Magnitude &first, const Magnitude &second)
{
	auto result = first;
	if (second.empty()) {
		return result;
	}
	auto resultIterator = result.rbegin();
	auto secondIterator = second.rbegin();
	bool borrow = false;
	while (resultIterator != result.rend())
	{
		if (!borrow && secondIterator == second.rend())
		{
			break;
		}
		int value = *resultIterator - (secondIterator == second.rend() ? 0 : *secondIterator++) - (borrow ? 1 : 0);
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
	remove_trailing_zeros(result);
	return result;
}

BigNumber operator+(const BigNumber &first, const BigNumber &second)
{
	if (first.sign == second.sign)
	{
		return { add(first.magnitude, second.magnitude), first.sign };
	}
	if (compare_magnitudes(first.magnitude, second.magnitude) > 0)
	{
		return { subtract_magnitudes(first.magnitude, second.magnitude), first.sign };
	}
	return { subtract_magnitudes(second.magnitude, first.magnitude), second.sign };
}

BigNumber operator-(const BigNumber &first, const BigNumber &second)
{
	return BigNumber(subtract_magnitudes(first.magnitude, second.magnitude));
}

std::ostream& operator<<( std::ostream& os, BigNumber const& value ) {
	os << (value.sign == Sign::PLUS ? '+' : '-');
	os << "BigNumber{";
	for (const auto &item : value.magnitude)
	{
		os << " " << item;
	}
	return os << " }";
}

BigNumber operator*(const BigNumber &first, const BigNumber &second)
{
	BigNumber result{{}};
	auto operand = first;
	for (auto &value : std::ranges::reverse_view(second.magnitude))
	{
		for (unsigned char mask = 0x01; mask != 0; mask <<= 1)
		{
			if ((value & mask) != 0)
			{
				result = result + operand;
			}
			operand <<= 1;
		}
	}
	return result;
}

BigNumber &operator<<=(BigNumber &number, size_t pos)
{
	if (number.magnitude.empty())
	{
		return number;
	}
	if (pos == 0)
	{
		return number;
	}
	number.magnitude.insert(number.magnitude.cend(), pos / 8, 0);
	pos %= 8;
	unsigned char carry = 0;
	for (auto &value : std::ranges::reverse_view(number.magnitude))
	{
		int result = (value << pos) + carry;
		value = result & 0xFF;
		carry = (result >> 8) & 0xFF;
	}
	if (carry > 0)
	{
		number.magnitude.insert(number.magnitude.cbegin(), carry);
	}
	return number;
}

BigNumber &operator>>=(BigNumber &number, size_t pos)
{
	if (number.magnitude.empty())
	{
		return number;
	}
	if (pos > 8)
	{
		number.magnitude.erase(number.magnitude.end() - pos / 8lu, number.magnitude.end());
		pos %= 8;
	}
	if (pos == 0)
	{
		return number;
	}
	unsigned char carry = 0;
	unsigned char carry_mask = ~(0xFF << pos);
	for (auto &value : number.magnitude)
	{
		unsigned char new_value = (value >> pos) + carry;
		carry = (value & carry_mask) << (8 - pos);
		value = new_value;
	}
	remove_trailing_zeros(number.magnitude);
	return number;
}

BigNumber operator%(const BigNumber &first, const BigNumber &second)
{
	if (first.magnitude.empty() || second.magnitude.empty())
	{
		return BigNumber({});
	}
	BigNumber divisor = second;
	BigNumber reminder = first;
	int bit_size = 0;
	while(divisor < reminder)
	{
		divisor <<= 1;
		++bit_size;
	}
	while (bit_size >= 0)
	{
		if (reminder == divisor)
		{
			return BigNumber({});
		}
		if (reminder > divisor) {
			reminder = reminder - divisor;
		}
		divisor >>= 1;
		--bit_size;
	}
	return reminder;
}

bool operator<(const BigNumber &first, const BigNumber &second)
{
	return compare_magnitudes(first.magnitude, second.magnitude) < 0;
}

bool operator>(const BigNumber &first, const BigNumber &second)
{
	return !(first == second || first < second);
}

BigNumber operator&(const BigNumber &first, const BigNumber &second)
{
	std::vector<unsigned char> result(std::max(first.magnitude.size(), second.magnitude.size()), 0);
	auto rI = result.rbegin();
	for (auto fI = first.magnitude.rbegin(), sI = second.magnitude.rbegin(); fI != first.magnitude.rend() && sI != second.magnitude.rend(); ++fI, ++sI, ++rI)
	{
		*rI = *fI & *sI;
	}
	remove_trailing_zeros(result);
	return BigNumber(result);
}

size_t BigNumber::bit_length() const
{
	if (magnitude.empty())
	{
		return 0;
	}
	int first_byte_size = 0;
	for (unsigned char mask = 0x01; mask <= magnitude.at(0) && mask != 0; mask <<= 1, first_byte_size++);
	return (magnitude.size() - 1) * 8 + first_byte_size;
}

std::vector<unsigned char> BigNumber::data()
{
	return magnitude;
}

bool BigNumber::operator==(const BigNumber &other) const
{
	if (magnitude != other.magnitude)
	{
		return false;
	}
	return magnitude.empty() || sign == other.sign;
}
