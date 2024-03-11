//
// Created by Margo on 09.03.2024.
//

#ifndef TLS_PLAYGROUND_MAIN_HPP
#define TLS_PLAYGROUND_MAIN_HPP

#include <array>
#include <stdexcept>
#include <vector>

/**
 * Set big endian bit to 1.
 *
 * @param index 1 based
 */
template<auto len>
void set_bit(std::array<unsigned char, len> &src, unsigned int index)
{
	auto &item = src.at((index - 1) / 8);
	item |= (0x80 >> (index - 1) % 8);
}

/**
 * Set big endian bit to 0.
 *
 * @param index 1 based
 */
template<auto len>
void clear_bit(std::array<unsigned char, len> &src, unsigned int index)
{
	auto &item = src.at((index - 1) / 8);
	item &= ~(0x80 >> (index - 1) % 8);
}

template<size_t len, typename Input>
void permute(std::array<unsigned char, len> &target,
		const Input &src,
		const std::array<unsigned int, len * 8> &permute_table)
{
	for (size_t i = 0; i < len * 8; ++i)
	{
		const auto index = permute_table.at(i);
		if (src.at((index - 1) / 8) & (0x80 >> ((index - 1) % 8)))
		{
			set_bit(target, i + 1);
		}
		else
		{
			clear_bit(target, i + 1);
		}
	}
}

void schedule_key_rotl(std::array<unsigned char, 7> &key);

std::array<std::array<unsigned char, 6>, 16> build_schedule_key(const std::array<unsigned char, 8> &key);

void des_block_encrypt(const std::array<unsigned char, 8> &input_block,
		std::array<unsigned char, 8> &output_block,
		const std::array<unsigned char, 8> &key);

#endif //TLS_PLAYGROUND_MAIN_HPP
