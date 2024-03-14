#include <algorithm>

#include "des.hpp"

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

void schedule_key_rotr(std::array<unsigned char, 7> &key)
{
	std::array<unsigned char, 7> copy = key;
	key[0] = (0xFE & copy[0]) >> 1 | (0x10 & copy[3]) << 3;
	key[1] = (0xFE & copy[1]) >> 1 | (0x01 & copy[0]) << 7;
	key[2] = (0xFE & copy[2]) >> 1 | (0x01 & copy[1]) << 7;
	key[3] = (0xEE & copy[3]) >> 1 | (0x01 & copy[2]) << 7 | (0x01 & copy[6]) << 3;
	key[4] = (0xFE & copy[4]) >> 1 | (0x01 & copy[3]) << 7;
	key[5] = (0xFE & copy[5]) >> 1 | (0x01 & copy[4]) << 7;
	key[6] = (0xFE & copy[6]) >> 1 | (0x01 & copy[5]) << 7;
}

const auto schedule_key_permutation_table = std::array<unsigned int, 56>{
		57, 49, 41, 33, 25, 17, 9, 1,
		58, 50, 42, 34, 26, 18, 10, 2,
		59, 51, 43, 35, 27, 19, 11, 3,
		60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15, 7,
		62, 54, 46, 38, 30, 22, 14, 6,
		61, 53, 45, 37, 29, 21, 13, 5,
		28, 20, 12, 4
};

const auto schedule_key_reduce_table = std::array<unsigned int, 48>{
		14, 17, 11, 24, 1, 5,
		3, 28, 15, 6, 21, 10,
		23, 19, 12, 4, 26, 8,
		16, 7, 27, 20, 13, 2,
		41, 52, 31, 37, 47, 55,
		30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53,
		46, 42, 50, 36, 29, 32
};

std::array<std::array<unsigned char, 6>, 16> build_encrypt_schedule_key(const std::array<unsigned char, 8> &key)
{
	std::array<unsigned char, 7> permuted_key;
	permute(permuted_key, key, schedule_key_permutation_table);
	std::array<std::array<unsigned char, 6>, 16> schedule_keys{};
	for (int round = 0; round < 16; round++)
	{
		schedule_key_rotl(permuted_key);
		if (!(round <= 1 || round == 8 || round == 15))
		{
			// Rotate twice except in rounds 1, 2, 9 & 16
			schedule_key_rotl(permuted_key);
		}
		permute(schedule_keys[round], permuted_key, schedule_key_reduce_table);
	}
	return schedule_keys;
}

std::array<std::array<unsigned char, 6>, 16> build_decrypt_schedule_key(const std::array<unsigned char, 8> &key)
{
	std::array<unsigned char, 7> permuted_key;
	permute(permuted_key, key, schedule_key_permutation_table);
	std::array<std::array<unsigned char, 6>, 16> schedule_keys{};
	for (int round = 0; round < 16; round++)
	{
		permute(schedule_keys[round], permuted_key, schedule_key_reduce_table);
		schedule_key_rotr(permuted_key);
		if (!(round >= 14 || round == 7 || round == 0))
		{
			// Rotate twice except in rounds 1, 2, 9 & 16
			schedule_key_rotr(permuted_key);
		}
	}
	return schedule_keys;
}

/**
 * Add 32 to each item as we are expending right 4 bytes of 8 byte array
 */
const auto des_expansion_table = std::array<unsigned int, 48>{
		32 + 32, 1 + 32, 2 + 32, 3 + 32, 4 + 32, 5 + 32,
		4 + 32, 5 + 32, 6 + 32, 7 + 32, 8 + 32, 9 + 32,
		8 + 32, 9 + 32, 10 + 32, 11 + 32, 12 + 32, 13 + 32,
		12 + 32, 13 + 32, 14 + 32, 15 + 32, 16 + 32, 17 + 32,
		16 + 32, 17 + 32, 18 + 32, 19 + 32, 20 + 32, 21 + 32,
		20 + 32, 21 + 32, 22 + 32, 23 + 32, 24 + 32, 25 + 32,
		24 + 32, 25 + 32, 26 + 32, 27 + 32, 28 + 32, 29 + 32,
		28 + 32, 29 + 32, 30 + 32, 31 + 32, 32 + 32, 1 + 32
};

const auto sbox_permute_table = std::array<unsigned int, 32>{
		16, 7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2, 8, 24, 14,
		32, 27, 3, 9,
		19, 13, 30, 6,
		22, 11, 4, 25
};

const auto sbox = std::array<std::array<unsigned char, 64>, 8>{
		std::array<unsigned char, 64>{ 14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1,
									   3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
									   4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7,
									   15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13 },
		std::array<unsigned char, 64>{ 15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
									   9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
									   0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
									   5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9 },
		std::array<unsigned char, 64>{ 10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10,
									   1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
									   13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7,
									   11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12 },
		std::array<unsigned char, 64>{ 7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3,
									   1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
									   10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8,
									   15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14 },
		std::array<unsigned char, 64>{ 2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1,
									   8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
									   4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13,
									   15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3 },
		std::array<unsigned char, 64>{ 12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5,
									   0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
									   9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10,
									   7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13 },
		std::array<unsigned char, 64>{ 4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10,
									   3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
									   1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7,
									   10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12 },
		std::array<unsigned char, 64>{ 13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4,
									   10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
									   7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13,
									   0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11 }
};

const auto final_permute_table = std::array<unsigned int, 64>{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41, 9, 49, 17, 57, 25
};

const auto initial_permute_table = std::array<unsigned int, 64>{
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6,
		64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7
};

void des_block_process(const std::array<unsigned char, 8> &input_block,
		std::array<unsigned char, 8> &output_block,
		std::array<std::array<unsigned char, 6>, 16> schedule_keys)
{
	std::array<unsigned char, 8> input_cypher;
	permute(input_cypher, input_block, initial_permute_table);
	for (const auto &round_key: schedule_keys)
	{
		std::array<unsigned char, 6> expanded_block;
		permute(expanded_block, input_cypher, des_expansion_table);
		std::transform(expanded_block.begin(), expanded_block.end(), round_key.cbegin(), expanded_block.begin(),
				[](const auto &left, const auto &right)
				{
					return left ^ right;
				});
		std::array<unsigned char, 4> sbox_block{};
		sbox_block[0] = sbox[0][(expanded_block[0] & 0xFC) >> 2] << 4;
		sbox_block[0] |= sbox[1][(expanded_block[0] & 0x03) << 4 | (expanded_block[1] & 0xF0) >> 4];
		sbox_block[1] = sbox[2][(expanded_block[1] & 0x0F) << 2 | (expanded_block[2] & 0xC0) >> 6] << 4;
		sbox_block[1] |= sbox[3][(expanded_block[2] & 0x3F)];
		sbox_block[2] = sbox[4][(expanded_block[3] & 0xFC) >> 2] << 4;
		sbox_block[2] |= sbox[5][(expanded_block[3] & 0x03) << 4 | (expanded_block[4] & 0xF0) >> 4];
		sbox_block[3] = sbox[6][(expanded_block[4] & 0x0F) << 2 | (expanded_block[5] & 0xC0) >> 6] << 4;
		sbox_block[3] |= sbox[7][(expanded_block[5] & 0x3F)];
		std::array<unsigned char, 4> sbox_permuted_block;
		permute(sbox_permuted_block, sbox_block, sbox_permute_table);
		std::transform(sbox_permuted_block.begin(), sbox_permuted_block.end(), input_cypher.cbegin(),
				sbox_permuted_block.begin(),
				[](const auto &left, const auto &right)
				{
					return left ^ right;
				});
		input_cypher[0] = input_cypher[4];
		input_cypher[1] = input_cypher[5];
		input_cypher[2] = input_cypher[6];
		input_cypher[3] = input_cypher[7];
		input_cypher[4] = sbox_permuted_block[0];
		input_cypher[5] = sbox_permuted_block[1];
		input_cypher[6] = sbox_permuted_block[2];
		input_cypher[7] = sbox_permuted_block[3];
	}
	std::swap(input_cypher[4], input_cypher[0]);
	std::swap(input_cypher[5], input_cypher[1]);
	std::swap(input_cypher[6], input_cypher[2]);
	std::swap(input_cypher[7], input_cypher[3]);
	permute(output_block, input_cypher, final_permute_table);
}

std::vector<unsigned char> des_ecb_pkcs5_encrypt(const std::vector<unsigned char> &data, const std::array<unsigned char, 8> &key)
{
	std::vector<unsigned char> result{};
	std::array<unsigned char, 8> input_block;
	std::array<unsigned char, 8> cypher_block;
	const auto schedule_keys = build_encrypt_schedule_key(key);
	for (size_t i = 0; i <= data.size(); i += 8)
	{
		if (i + 8 < data.size())
		{
			std::copy_n(data.cbegin() + i, 8, input_block.begin());
			des_block_process(input_block, cypher_block, schedule_keys);
			std::copy_n(cypher_block.cbegin(), 8, std::back_inserter(result));
		}
		else
		{
			input_block.fill(i + 8 - data.size());
			std::copy_n(data.cbegin() + i, data.size() - i, input_block.begin());
			des_block_process(input_block, cypher_block, schedule_keys);
			std::copy_n(cypher_block.cbegin(), 8, std::back_inserter(result));
		}
	}
	return result;
}

std::vector<unsigned char> des_ecb_pkcs5_decrypt(const std::vector<unsigned char> &data, const std::array<unsigned char, 8> &key)
{
	if (data.empty() || data.size() % 8 != 0)
	{
		throw std::runtime_error("Malformed cypher data");
	}
	std::vector<unsigned char> result{};
	std::array<unsigned char, 8> input_block;
	std::array<unsigned char, 8> output_block;
	const auto schedule_keys = build_decrypt_schedule_key(key);
	for (size_t i = 0; i < data.size(); i += 8)
	{
		std::copy_n(data.cbegin() + i, 8, input_block.begin());
		des_block_process(input_block, output_block, schedule_keys);
		std::copy_n(output_block.cbegin(), 8, std::back_inserter(result));
	}
	if (result.back() > 8 || result.back() < 1)
	{
		throw std::runtime_error("PKCS5 padding expected");
	}
	result.resize(result.size() - result.back());
	return result;
}

std::vector<unsigned char> des_cbc_pkcs5_encrypt(const std::vector<unsigned char> &data, const std::array<unsigned char, 8> &key, const std::array<unsigned char, 8> &iv)
{
	std::vector<unsigned char> result{};
	std::array<unsigned char, 8> input_block;
	std::array<unsigned char, 8> cypher_block = iv;
	const auto schedule_keys = build_encrypt_schedule_key(key);
	for (size_t i = 0; i <= data.size(); i += 8)
	{
		if (i + 8 < data.size())
		{
			std::copy_n(data.cbegin() + i, 8, input_block.begin());
			std::transform(input_block.begin(), input_block.end(), cypher_block.cbegin(),
					input_block.begin(),
					[](const auto &left, const auto &right)
					{
						return left ^ right;
					});
			des_block_process(input_block, cypher_block, schedule_keys);
			std::copy_n(cypher_block.cbegin(), 8, std::back_inserter(result));
		}
		else
		{
			input_block.fill(i + 8 - data.size());
			std::copy_n(data.cbegin() + i, data.size() - i, input_block.begin());
			std::transform(input_block.begin(), input_block.end(), cypher_block.cbegin(),
					input_block.begin(),
					[](const auto &left, const auto &right)
					{
						return left ^ right;
					});
			des_block_process(input_block, cypher_block, schedule_keys);
			std::copy_n(cypher_block.cbegin(), 8, std::back_inserter(result));
		}
	}
	return result;
}

std::vector<unsigned char> des_cbc_pkcs5_decrypt(const std::vector<unsigned char> &data, const std::array<unsigned char, 8> &key, const std::array<unsigned char, 8> &iv)
{
	if (data.empty() || data.size() % 8 != 0)
	{
		throw std::runtime_error("Malformed cypher data");
	}
	std::vector<unsigned char> result{};
	std::array<unsigned char, 8> input_block;
	std::array<unsigned char, 8> output_block;
	auto next_iv = iv;
	const auto schedule_keys = build_decrypt_schedule_key(key);
	for (size_t i = 0; i < data.size(); i += 8)
	{
		std::copy_n(data.cbegin() + i, 8, input_block.begin());
		des_block_process(input_block, output_block, schedule_keys);
		std::transform(output_block.begin(), output_block.end(), next_iv.cbegin(),
				output_block.begin(),
				[](const auto &left, const auto &right)
				{
					return left ^ right;
				});
		next_iv = input_block;
		std::copy_n(output_block.cbegin(), 8, std::back_inserter(result));
	}
	if (result.back() > 8 || result.back() < 1)
	{
		throw std::runtime_error("PKCS5 padding expected");
	}
	result.resize(result.size() - result.back());
	return result;
}