#include <algorithm>
#include <array>
#include <cstdint>

#include "sha.hpp"

uint_fast32_t ch(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & y) ^ (~x & z);
}

uint_fast32_t maj(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
{
	return (x & y) ^ (x & z) ^ (y & z);
}

struct sha1
{

	const std::array<uint_fast32_t, 4> round_constants{
			0x5a827999,
			0x6ed9eba1,
			0x8f1bbcdc,
			0xca62c1d6
	};


	static uint_fast32_t parity(uint_fast32_t x, uint_fast32_t y, uint_fast32_t z)
	{
		return x ^ y ^ z;
	}

	void block_hash(const std::array<unsigned char, 64> &block, std::array<uint_fast32_t, 5> &hash)
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
				W[t] = (W[t] << 1) | ((W[t] & 0x80000000) >> 31);
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

	const std::array<uint_fast32_t, 5> initial_hash{
			0x67452301,
			0xefcdab89,
			0x98badcfe,
			0x10325476,
			0xc3d2e1f0
	};
};

consteval std::array<uint_fast32_t, 8> compute_sha256_initial_hash() {
	std::array<uint_fast32_t, 8> hash{
			0x67e6096a,
			0x85ae67bb,
			0x72f36e3c,
			0x3af54fa5,
			0x7f520e51,
			0x8c68059b,
			0xabd9831f,
			0x19cde05b
	};
	for (unsigned long & i : hash)
	{
		i = (i & 0xFF) << 24
			| (i & 0xFF00) << 8
			| (i & 0xFF0000) >> 8
			| (i & 0xFF000000) >> 24;
	}
	return hash;
}

struct sha256
{
	uint_fast32_t rotr(uint_fast32_t x, uint_fast32_t n)
	{
		return (((x & 0xFFFFFFFF) >> n) | (x << (32 - n))) & 0xFFFFFFFF;
	}

	uint_fast32_t shr(uint_fast32_t x, uint_fast32_t n)
	{
		return (x & 0xFFFFFFFF) >> n;
	}

	uint_fast32_t sigma_rot(uint_fast32_t x, int i)
	{
		return rotr(x, i ? 6 : 2) ^ rotr(x, i ? 11 : 13) ^ rotr(x, i ? 25 : 22);
	}

	uint_fast32_t sigma_shr(uint_fast32_t x, int i)
	{
		return rotr(x, i ? 17 : 7) ^ rotr(x, i ? 19 : 18) ^ shr(x, i ? 10 : 3);
	}

	constexpr static const std::array<uint_fast32_t, 64> k{
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
			0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
			0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
			0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
			0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
			0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	void block_hash(const std::array<unsigned char, 64> &block, std::array<uint_fast32_t, 8> &hash)
	{
		std::array<uint_fast32_t, 64> W{};
		uint_fast32_t a, b, c, d, e, f, g, h;
		uint_fast32_t T1, T2;
		int t, i;

		for (t = 0; t < 64; t++)
		{
			if (t <= 15)
			{
				W[t] = (block[(t * 4)] << 24) |
					   (block[(t * 4) + 1] << 16) |
					   (block[(t * 4) + 2] << 8) |
					   (block[(t * 4) + 3]);
			}
			else
			{
				W[t] = (sigma_shr(W[t - 2], 1) +
						W[t - 7] +
						sigma_shr(W[t - 15], 0) +
						W[t - 16]) & 0xFFFFFFFF;
			}
		}
		a = hash[0];
		b = hash[1];
		c = hash[2];
		d = hash[3];
		e = hash[4];
		f = hash[5];
		g = hash[6];
		h = hash[7];
		for (t = 0; t < 64; t++)
		{
			T1 = (h + sigma_rot(e, 1) + ch(e, f, g) + k[t] + W[t]) & 0xFFFFFFFF;
			T2 = (sigma_rot(a, 0) + maj(a, b, c)) & 0xFFFFFFFF;
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}
		hash[0] = a + hash[0];
		hash[1] = b + hash[1];
		hash[2] = c + hash[2];
		hash[3] = d + hash[3];
		hash[4] = e + hash[4];
		hash[5] = f + hash[5];
		hash[6] = g + hash[6];
		hash[7] = h + hash[7];
	}

	const std::array<uint_fast32_t, 8> initial_hash = compute_sha256_initial_hash();
};

template<uint hash_size, class SHA>
std::array<unsigned char, hash_size> sha_hash(SHA sha, const std::vector<unsigned char> &input)
{
	std::array<uint_fast32_t, hash_size / 4> hash = sha.initial_hash;
	std::array<unsigned char, 64> block{};
	for (size_t i = 0; i <= input.size(); i += block.size())
	{
		const auto payload_size = std::min(input.size() - i, block.size());
		if (payload_size == block.size())
		{
			std::copy_n(input.begin() + i, payload_size, block.begin());
			sha.block_hash(block, hash);
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
			sha.block_hash(block, hash);
		}
		else
		{
			std::fill(block.begin(), block.end(), 0);
			std::copy_n(input.begin() + i, payload_size, block.begin());
			block[payload_size] = 0x80;
			sha.block_hash(block, hash);
			std::fill(block.begin(), block.end(), 0);
			block[block.size() - 8] = (input.size() * 8 & 0xFF00000000000000) >> 56;
			block[block.size() - 7] = (input.size() * 8 & 0x00FF000000000000) >> 48;
			block[block.size() - 6] = (input.size() * 8 & 0x0000FF0000000000) >> 40;
			block[block.size() - 5] = (input.size() * 8 & 0x000000FF00000000) >> 32;
			block[block.size() - 4] = (input.size() * 8 & 0xFF000000) >> 24;
			block[block.size() - 3] = (input.size() * 8 & 0x00FF0000) >> 16;
			block[block.size() - 2] = (input.size() * 8 & 0x0000FF00) >> 8;
			block[block.size() - 1] = (input.size() * 8 & 0x000000FF);
			sha.block_hash(block, hash);
		}
	}
	std::array<unsigned char, hash_size> result{};
	for (size_t i = 0; i < result.size(); ++i)
	{
		result[i] = (hash[i / 4] >> ((3 - (i % 4)) * 8)) & 0xFF;
	}
	return result;
}

std::array<unsigned char, 20> sha1_hash(const std::vector<unsigned char> &input)
{
	return sha_hash<20>(sha1{}, input);
}


std::array<unsigned char, 32> sha256_hash(const std::vector<unsigned char> &input)
{
	return sha_hash<32>(sha256{}, input);
}