#ifndef TLS_PLAYGROUND_TLS_PRF_HPP
#define TLS_PLAYGROUND_TLS_PRF_HPP

#include <array>
#include <vector>

void prf(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed, std::vector<unsigned char> &out);

std::vector<unsigned char> compute_master_secret(
		const std::array<unsigned char, 48> &premaster_secret,
		const std::array<unsigned char, 32> &client_random,
		const std::array<unsigned char, 32> &server_random);

#endif //TLS_PLAYGROUND_TLS_PRF_HPP
