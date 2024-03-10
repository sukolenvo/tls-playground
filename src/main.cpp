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

const auto schedule_key_permutation_table = std::vector<unsigned int> {
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7,
	62, 54, 46, 38, 30, 22, 14, 6,
	61, 53, 45, 37, 29, 21, 13, 5,
	28, 20, 12, 4
};

const auto des_expansion_table = std::vector<unsigned int>{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

std::array<std::array<unsigned char, 7>, 16> build_schedule_key(const std::array<unsigned char, 8> &key)
{
	std::array<unsigned char, 7> permuted_key;
	permute(permuted_key, key, schedule_key_permutation_table);
	std::array<std::array<unsigned char, 7>, 16> schedule_keys{};
	for (int round = 0; round < 16; round++ ) {
		schedule_key_rotl(permuted_key);
		if ( !( round <= 1 || round == 8 || round == 15 ) )
		{
			// Rotate twice except in rounds 1, 2, 9 & 16
			schedule_key_rotl( permuted_key );
		}
		schedule_keys[round] = permuted_key;
	}
	return schedule_keys;
}

void des_block_encrypt(const std::array<unsigned char, 8> &input_block,
					   std::array<unsigned char, 8> &output_block,
					   const std::array<unsigned char, 8> &key)
{
	permute(output_block, input_block, initial_permute_table);
	const auto schedule_keys = build_schedule_key(key);
}
