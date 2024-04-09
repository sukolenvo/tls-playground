#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>

#include "md5.hpp"

uint_fast32_t F(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & y) | (~x & z);
}

uint_fast32_t G(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & z) | (y & ~z);
}

uint_fast32_t H(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x ^ y ^ z);
}

uint_fast32_t I(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return y ^ (x | ~z);
}

void md5_block_hash(const std::array<unsigned char, 64> &input, std::array<uint_fast32_t, 4> &hash)
{
	uint_fast32_t a, b, c, d;
	int j;
	std::array<uint_fast32_t, 16> x{};
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	for (j = 0; j < 16; j++)
	{
		x[j] = input[(j * 4) + 3] << 24 |
			   input[(j * 4) + 2] << 16 |
			   input[(j * 4) + 1] << 8 |
			   input[(j * 4)];
	}
	const auto round = [&](auto F, auto &a, auto b, auto c, auto d, auto k, auto s, auto i)
	{
		a = (a + F(b, c, d) + x[k] + (uint_fast32_t)(4294967296 * fabs(sin((double)i))));
		a &= 0xffffffff;
		a = (a << s) | (a >> (32 - s));
		a &= 0xffffffff;
		a += b;
		a &= 0xffffffff;
	};
	// Round 1
	round(F, a, b, c, d, 0, 7, 1);
	round(F, d, a, b, c, 1, 12, 2);
	round(F, c, d, a, b, 2, 17, 3);
	round(F, b, c, d, a, 3, 22, 4);
	round(F, a, b, c, d, 4, 7, 5);
	round(F, d, a, b, c, 5, 12, 6);
	round(F, c, d, a, b, 6, 17, 7);
	round(F, b, c, d, a, 7, 22, 8);
	round(F, a, b, c, d, 8, 7, 9);
	round(F, d, a, b, c, 9, 12, 10);
	round(F, c, d, a, b, 10, 17, 11);
	round(F, b, c, d, a, 11, 22, 12);
	round(F, a, b, c, d, 12, 7, 13);
	round(F, d, a, b, c, 13, 12, 14);
	round(F, c, d, a, b, 14, 17, 15);
	round(F, b, c, d, a, 15, 22, 16);

	// Round 2
	round(G, a, b, c, d, 1, 5, 17);
	round(G, d, a, b, c, 6, 9, 18);
	round(G, c, d, a, b, 11, 14, 19);
	round(G, b, c, d, a, 0, 20, 20);
	round(G, a, b, c, d, 5, 5, 21);
	round(G, d, a, b, c, 10, 9, 22);
	round(G, c, d, a, b, 15, 14, 23);
	round(G, b, c, d, a, 4, 20, 24);
	round(G, a, b, c, d, 9, 5, 25);
	round(G, d, a, b, c, 14, 9, 26);
	round(G, c, d, a, b, 3, 14, 27);
	round(G, b, c, d, a, 8, 20, 28);
	round(G, a, b, c, d, 13, 5, 29);
	round(G, d, a, b, c, 2, 9, 30);
	round(G, c, d, a, b, 7, 14, 31);
	round(G, b, c, d, a, 12, 20, 32);

	// Round 3
	round(H, a, b, c, d, 5, 4, 33);
	round(H, d, a, b, c, 8, 11, 34);
	round(H, c, d, a, b, 11, 16, 35);
	round(H, b, c, d, a, 14, 23, 36);
	round(H, a, b, c, d, 1, 4, 37);
	round(H, d, a, b, c, 4, 11, 38);
	round(H, c, d, a, b, 7, 16, 39);
	round(H, b, c, d, a, 10, 23, 40);
	round(H, a, b, c, d, 13, 4, 41);
	round(H, d, a, b, c, 0, 11, 42);
	round(H, c, d, a, b, 3, 16, 43);
	round(H, b, c, d, a, 6, 23, 44);
	round(H, a, b, c, d, 9, 4, 45);
	round(H, d, a, b, c, 12, 11, 46);
	round(H, c, d, a, b, 15, 16, 47);
	round(H, b, c, d, a, 2, 23, 48);

	// Round 4
	round(I, a, b, c, d, 0, 6, 49);
	round(I, d, a, b, c, 7, 10, 50);
	round(I, c, d, a, b, 14, 15, 51);
	round(I, b, c, d, a, 5, 21, 52);
	round(I, a, b, c, d, 12, 6, 53);
	round(I, d, a, b, c, 3, 10, 54);
	round(I, c, d, a, b, 10, 15, 55);
	round(I, b, c, d, a, 1, 21, 56);
	round(I, a, b, c, d, 8, 6, 57);
	round(I, d, a, b, c, 15, 10, 58);
	round(I, c, d, a, b, 6, 15, 59);
	round(I, b, c, d, a, 13, 21, 60);
	round(I, a, b, c, d, 4, 6, 61);
	round(I, d, a, b, c, 11, 10, 62);
	round(I, c, d, a, b, 2, 15, 63);
	round(I, b, c, d, a, 9, 21, 64);

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
}

const auto initial_hash = std::array<uint_fast32_t, 4>{
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476
};

std::array<unsigned char, 16> md5_hash(const std::vector<unsigned char> &input)
{
	Md5Hashing hashing{};
	hashing.append(input);
	return hashing.close();
}

Md5Hashing::Md5Hashing() : state(initial_hash)
{

}

void Md5Hashing::append(const std::vector<unsigned char> &input)
{
	auto remains = input.size();
	auto input_iter = input.begin();
	while (remains > 0)
	{
		auto copy = std::min(block_buffer.size() - buffer_pos, remains);
		std::copy_n(input_iter, copy, block_buffer.begin() + buffer_pos);
		buffer_pos += copy;
		remains -= copy;
		input_iter += copy;
		if (buffer_pos == block_buffer.size())
		{
			md5_block_hash(block_buffer, state);
			buffer_pos = 0;
		}
	}
	input_size += input.size();
}

std::array<unsigned char, 16> Md5Hashing::close()
{
	if (buffer_pos <= block_buffer.size() - 9)
	{
		std::fill(block_buffer.begin() + buffer_pos, block_buffer.end() - 8, 0);
		block_buffer[buffer_pos] = 0x80;
		block_buffer[block_buffer.size() - 1] = (input_size * 8 & 0xFF00000000000000) >> 56;
		block_buffer[block_buffer.size() - 2] = (input_size * 8 & 0x00FF000000000000) >> 48;
		block_buffer[block_buffer.size() - 3] = (input_size * 8 & 0x0000FF0000000000) >> 40;
		block_buffer[block_buffer.size() - 4] = (input_size * 8 & 0x000000FF00000000) >> 32;
		block_buffer[block_buffer.size() - 5] = (input_size * 8 & 0xFF000000) >> 24;
		block_buffer[block_buffer.size() - 6] = (input_size * 8 & 0x00FF0000) >> 16;
		block_buffer[block_buffer.size() - 7] = (input_size * 8 & 0x0000FF00) >> 8;
		block_buffer[block_buffer.size() - 8] = (input_size * 8 & 0x000000FF);
		md5_block_hash(block_buffer, state);
	}
	else
	{
		std::fill(block_buffer.begin() + buffer_pos, block_buffer.end(), 0);
		block_buffer[buffer_pos] = 0x80;
		md5_block_hash(block_buffer, state);
		std::fill(block_buffer.begin(), block_buffer.end() - 8, 0);
		block_buffer[block_buffer.size() - 1] = (input_size * 8 & 0xFF00000000000000) >> 56;
		block_buffer[block_buffer.size() - 2] = (input_size * 8 & 0x00FF000000000000) >> 48;
		block_buffer[block_buffer.size() - 3] = (input_size * 8 & 0x0000FF0000000000) >> 40;
		block_buffer[block_buffer.size() - 4] = (input_size * 8 & 0x000000FF00000000) >> 32;
		block_buffer[block_buffer.size() - 5] = (input_size * 8 & 0xFF000000) >> 24;
		block_buffer[block_buffer.size() - 6] = (input_size * 8 & 0x00FF0000) >> 16;
		block_buffer[block_buffer.size() - 7] = (input_size * 8 & 0x0000FF00) >> 8;
		block_buffer[block_buffer.size() - 8] = (input_size * 8 & 0x000000FF);
		md5_block_hash(block_buffer, state);
	}
	std::array<unsigned char, 16> result{
			static_cast<unsigned char>(state[0] & 0xFF),
			static_cast<unsigned char>((state[0] & 0xFF00) >> 8),
			static_cast<unsigned char>((state[0] & 0xFF0000) >> 16),
			static_cast<unsigned char>((state[0] & 0xFF000000) >> 24),
			static_cast<unsigned char>(state[1] & 0xFF),
			static_cast<unsigned char>((state[1] & 0xFF00) >> 8),
			static_cast<unsigned char>((state[1] & 0xFF0000) >> 16),
			static_cast<unsigned char>((state[1] & 0xFF000000) >> 24),
			static_cast<unsigned char>(state[2] & 0xFF),
			static_cast<unsigned char>((state[2] & 0xFF00) >> 8),
			static_cast<unsigned char>((state[2] & 0xFF0000) >> 16),
			static_cast<unsigned char>((state[2] & 0xFF000000) >> 24),
			static_cast<unsigned char>(state[3] & 0xFF),
			static_cast<unsigned char>((state[3] & 0xFF00) >> 8),
			static_cast<unsigned char>((state[3] & 0xFF0000) >> 16),
			static_cast<unsigned char>((state[3] & 0xFF000000) >> 24)
	};
	input_size = 0;
	buffer_pos = 0;
	state = initial_hash;
	return result;
}
