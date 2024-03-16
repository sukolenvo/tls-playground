#ifndef TLS_PLAYGROUND_AES_HPP
#define TLS_PLAYGROUND_AES_HPP

#include <array>

std::vector<unsigned char> aes128_cbc_encrypt(const std::vector<unsigned char> &input,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 16> &key);

std::vector<unsigned char> aes128_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 16> &key);

std::vector<unsigned char> aes192_cbc_encrypt(const std::vector<unsigned char> &input,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 24> &key);

std::vector<unsigned char> aes192_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 24> &key);

std::vector<unsigned char> aes256_cbc_encrypt(const std::vector<unsigned char> &input,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 32> &key);

std::vector<unsigned char> aes256_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
		const std::array<unsigned char, 16> &iv,
		const std::array<unsigned char, 32> &key);

#endif //TLS_PLAYGROUND_AES_HPP
