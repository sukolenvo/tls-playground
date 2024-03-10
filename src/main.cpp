#include <bit>

#include "main.hpp"

bool get_bit(const std::vector<unsigned char>::const_iterator &src, unsigned int index)
{
	if (index > 64) {
		throw std::runtime_error("index is out of range");
	}
	return *(src + (index - 1) / 8) & (0x80 >> ((index - 1) % 8));
}

void set_bit(std::vector<unsigned char> &src, unsigned int index)
{
	auto &item = src.at((index - 1) / 8);
	item |= (0x80 >> (index - 1) % 8);
}

void clear_bit(std::vector<unsigned char> &src, unsigned int index)
{
	auto &item = src.at((index - 1) / 8);
	item &= ~(0x80 >> (index - 1) % 8);
}

void permute(std::vector<unsigned char> &target,
			 std::vector<unsigned char> &src,
			 std::vector<unsigned int> permute_table)
{
	if (permute_table.size() != target.size() * 8) {
		throw std::runtime_error("permute table size doesn't match target size");
	}
	if (src.size() > target.size()) {
		throw std::runtime_error("unexpected source size");
	}
	for (int i = 0; i < src.size() * 8; ++i) {
		if (get_bit(src.cbegin(), permute_table.at(i))) {
			set_bit(target, i + 1);
		}
		else {
			clear_bit(target, i + 1);
		}
	}
}

void schedule_key_rotl(std::array<unsigned char, 7> &key)
{
	std::array<unsigned char, 7> copy = key;
	key[0] = (0x7F & copy[0]) << 1 | (0x80 & copy[1]) >> 7;
	key[1] = (0x7F & copy[1]) << 1 | (0x80 & copy[2]) >> 7;
	key[2] = (0x7F & copy[2]) << 1 | (0x80 & copy[3]) >> 7;
	key[3] = (0x77 & copy[3]) << 1 | (0x80 & copy[0]) >> 3 | (0x80 & copy[4]) >> 7;
	key[4] = (0x7F & copy[4]) << 1 | (0x80 & copy[5]) >> 7;
	key[5] = (0x7F & copy[5]) << 1 | (0x80 & copy[6]) >> 7;
	key[6] = (0x7F & copy[6]) << 1 | (0x08 & copy[3]) >> 3;
}
