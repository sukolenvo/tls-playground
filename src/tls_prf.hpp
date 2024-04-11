#ifndef TLS_PLAYGROUND_TLS_PRF_HPP
#define TLS_PLAYGROUND_TLS_PRF_HPP

#include <array>
#include <cstddef>
#include <string>
#include <vector>

void prf(const std::vector<unsigned char> &secret,
        const std::vector<unsigned char> &seed,
        std::vector<unsigned char> &out);

std::vector<unsigned char> prf(
        const std::vector<unsigned char> &secret,
        const std::string &label,
        const std::vector<unsigned char> &seed,
        size_t length);

std::vector<unsigned char> compute_master_secret(
        const std::array<unsigned char, 48> &premaster_secret,
        const std::array<unsigned char, 32> &client_random,
        const std::array<unsigned char, 32> &server_random);

std::vector<unsigned char> compute_key_expansion(
        const std::vector<unsigned char> &master_secret,
        const std::array<unsigned char, 32> &client_random,
        const std::array<unsigned char, 32> &server_random,
        size_t key_size);

#endif //TLS_PLAYGROUND_TLS_PRF_HPP
