#ifndef TLS_PLAYGROUND_TLS_PRF_HPP
#define TLS_PLAYGROUND_TLS_PRF_HPP

#include <array>
#include <string>
#include <vector>

void prf(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed, std::vector<unsigned char> &out);

std::vector<unsigned char> compute_master_secret(
		const std::array<unsigned char, 48> &premaster_secret,
		const std::array<unsigned char, 32> &client_random,
		const std::array<unsigned char, 32> &server_random);

std::vector<unsigned char> compute_verify_data(
		const std::vector<unsigned char> &master_secret,
		const std::string &label,
		const std::array<unsigned char, 16> &md5_hash,
		const std::array<unsigned char, 20> &sha1_hash);

std::vector<unsigned char> compute_key_expansion(
		const std::vector<unsigned char> &master_secret,
		const std::array<unsigned char, 32> &client_random,
		const std::array<unsigned char, 32> &server_random,
		size_t key_size);

#endif //TLS_PLAYGROUND_TLS_PRF_HPP
