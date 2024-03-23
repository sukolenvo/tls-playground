#include <algorithm>
#include <array>
#include <cstdint>

#include "sha.hpp"

const std::array<uint_fast32_t, 4> round_constants{
		0x5a827999,
		0x6ed9eba1,
		0x8f1bbcdc,
		0xca62c1d6
};

uint_fast32_t ch(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & y) ^ (~x & z);
}

uint_fast32_t parity(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return x ^ y ^ z;
}

uint_fast32_t maj(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

void sha1_block_hash(const std::array<unsigned char, 64> &block, std::array<uint_fast32_t, 5> &hash)
{
	std::array<uint_fast32_t, 80> W{};
	uint_fast32_t a, b, c, d, e;
	for (size_t t = 0; t < W.size(); t++)
	{
		if (t < 16)
		{
			W[t] = ((block[(t * 4)] << 24) |
				   (block[(t * 4) + 1] << 16) |
				   (block[(t * 4) + 2] << 8) |
				   (block[(t * 4) + 3])) & 0xFFFFFFFF;
		}
		else
		{
			W[t] = W[t - 3] ^
				   W[t - 8] ^
				   W[t - 14] ^
				   W[t - 16];
			// 32 bit rotl
			W[ t ] = ( W[ t ] << 1 ) | ( ( W[ t ] & 0x80000000 ) >> 31 );
		}
	}
	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];
	for (size_t t = 0; t < W.size(); t++)
	{
		auto T = (((a << 5) | ((a & 0xFFFFFFFF) >> 27)) + e + round_constants.at(t / 20) + W[t]) & 0xFFFFFFFF;
		if (t <= 19)
		{
			T += ch(b, c, d);
		}
		else if (t <= 39)
		{
			T += parity(b, c, d);
		}
		else if (t <= 59)
		{
			T += maj(b, c, d);
		}
		else
		{
			T += parity(b, c, d);
		}
		e = d;
		d = c;
		c = ((b << 30) | ((b & 0xFFFFFFFF) >> 2)) & 0xFFFFFFFF;
		b = a;
		a = T;
	}
	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

const auto initial_hash = std::array<uint_fast32_t, 5>{
		0x67452301,
		0xefcdab89,
		0x98badcfe,
		0x10325476,
		0xc3d2e1f0
};

std::array<unsigned char, 20> sha1_hash(const std::vector<unsigned char> &input)
{
	std::array<uint_fast32_t, 5> hash = initial_hash;
	std::array<unsigned char, 64> block{};
	for (size_t i = 0; i <= input.size(); i += block.size())
	{
		const auto payload_size = std::min(input.size() - i, block.size());
		if (payload_size == block.size())
		{
			std::copy_n(input.begin() + i, payload_size, block.begin());
			sha1_block_hash(block, hash);
		}
		else if (payload_size <= block.size() - 9)
		{
			std::fill(block.begin(), block.end(), 0);
			std::copy_n(input.begin() + i, payload_size, block.begin());
			block[payload_size] = 0x80;
			block[block.size() - 8] = (input.size() * 8 & 0xFF00000000000000) >> 56;
			block[block.size() - 7] = (input.size() * 8 & 0x00FF000000000000) >> 48;
			block[block.size() - 6] = (input.size() * 8 & 0x0000FF0000000000) >> 40;
			block[block.size() - 5] = (input.size() * 8 & 0x000000FF00000000) >> 32;
			block[block.size() - 4] = (input.size() * 8 & 0xFF000000) >> 24;
			block[block.size() - 3] = (input.size() * 8 & 0x00FF0000) >> 16;
			block[block.size() - 2] = (input.size() * 8 & 0x0000FF00) >> 8;
			block[block.size() - 1] = (input.size() * 8 & 0x000000FF);
			sha1_block_hash(block, hash);
		}
		else
		{
			std::fill(block.begin(), block.end(), 0);
			std::copy_n(input.begin() + i, payload_size, block.begin());
			block[payload_size] = 0x80;
			sha1_block_hash(block, hash);
			std::fill(block.begin(), block.end(), 0);
			block[block.size() - 8] = (input.size() * 8 & 0xFF00000000000000) >> 56;
			block[block.size() - 7] = (input.size() * 8 & 0x00FF000000000000) >> 48;
			block[block.size() - 6] = (input.size() * 8 & 0x0000FF0000000000) >> 40;
			block[block.size() - 5] = (input.size() * 8 & 0x000000FF00000000) >> 32;
			block[block.size() - 4] = (input.size() * 8 & 0xFF000000) >> 24;
			block[block.size() - 3] = (input.size() * 8 & 0x00FF0000) >> 16;
			block[block.size() - 2] = (input.size() * 8 & 0x0000FF00) >> 8;
			block[block.size() - 1] = (input.size() * 8 & 0x000000FF);
			sha1_block_hash(block, hash);
		}
	}
	return {
			static_cast<unsigned char>((hash[0] & 0xFF000000) >> 24),
			static_cast<unsigned char>((hash[0] & 0xFF0000) >> 16),
			static_cast<unsigned char>((hash[0] & 0xFF00) >> 8),
			static_cast<unsigned char>(hash[0] & 0xFF),
			static_cast<unsigned char>((hash[1] & 0xFF000000) >> 24),
			static_cast<unsigned char>((hash[1] & 0xFF0000) >> 16),
			static_cast<unsigned char>((hash[1] & 0xFF00) >> 8),
			static_cast<unsigned char>(hash[1] & 0xFF),
			static_cast<unsigned char>((hash[2] & 0xFF000000) >> 24),
			static_cast<unsigned char>((hash[2] & 0xFF0000) >> 16),
			static_cast<unsigned char>((hash[2] & 0xFF00) >> 8),
			static_cast<unsigned char>(hash[2] & 0xFF),
			static_cast<unsigned char>((hash[3] & 0xFF000000) >> 24),
			static_cast<unsigned char>((hash[3] & 0xFF0000) >> 16),
			static_cast<unsigned char>((hash[3] & 0xFF00) >> 8),
			static_cast<unsigned char>(hash[3] & 0xFF),
			static_cast<unsigned char>((hash[4] & 0xFF000000) >> 24),
			static_cast<unsigned char>((hash[4] & 0xFF0000) >> 16),
			static_cast<unsigned char>((hash[4] & 0xFF00) >> 8),
			static_cast<unsigned char>(hash[4] & 0xFF)
	};
}