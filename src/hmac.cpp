#include <cstddef>

#include "sha.hpp"
#include "hmac.hpp"

std::array<unsigned char, 32> hmac_sha256(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key)
{
	if (key.size() > 64)
	{
		const auto key_hash = sha256_hash(key);
		return hmac_sha256(input, { key_hash.begin(), key_hash.end() });
	}
	std::vector<unsigned char> block(64, 0x36);
	for (size_t i = 0; i < key.size(); ++i)
	{
		block[i] ^= key[i];
	}
	block.insert(block.cend(), input.begin(), input.end());
	const auto round1_hash = sha256_hash(block);
	block.resize(64 + round1_hash.size());
	for (size_t i = 0; i < 64; ++i)
	{
		block[i] = 0x5c;
	}
	for (size_t i = 0; i < key.size(); ++i)
	{
		block[i] ^= key[i];
	}
	for (size_t i = 0; i < round1_hash.size(); ++i)
	{
		block[i + 64] = round1_hash[i];
	}
	return sha256_hash(block);
}