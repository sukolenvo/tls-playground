#include <cstddef>

#include "sha.hpp"
#include "md5.hpp"
#include "hmac.hpp"

template<int hash_length>
std::array<unsigned char, hash_length> hmac(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key,
		const auto hash_func)
{
	if (key.size() > 64)
	{
		const auto key_hash = hash_func(key);
		return hmac<hash_length>(input, { key_hash.begin(), key_hash.end() }, hash_func);
	}
	std::vector<unsigned char> block(64, 0x36);
	for (size_t i = 0; i < key.size(); ++i)
	{
		block[i] ^= key[i];
	}
	block.insert(block.cend(), input.begin(), input.end());
	const auto round1_hash = hash_func(block);
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
	return hash_func(block);
}

std::array<unsigned char, 32> hmac_sha256(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key)
{
	return hmac<32>(input, key, &sha256_hash);
}

std::array<unsigned char, 16> hmac_md5(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key)
{
	return hmac<16>(input, key, &md5_hash);
}