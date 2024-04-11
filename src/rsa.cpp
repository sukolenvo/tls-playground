#include <algorithm>
#include <iterator>
#include <vector>

#include "rsa.hpp"

BigNumber rsa_compute(const BigNumber &message, const BigNumber &exp, const BigNumber &modulus)
{
    return message.power_modulus(exp, modulus);
}

std::vector<unsigned char> rsa_encrypt(
        const std::vector<unsigned char> &input,
        const BigNumber &public_key,
        const BigNumber &modulus)
{
    if (modulus.bit_length() % 8 != 0)
    {
        throw std::runtime_error("modulus bit length must be multiple of 8");
    }
    if (modulus.bit_length() / 8 <= 11)
    {
        throw std::runtime_error("modulus should be at least 12 bytes");
    }
    std::vector<unsigned char> output{};
    std::vector<unsigned char> block(modulus.bit_length() / 8, 0);
    for (size_t i = 0; i < input.size();)
    {
        const auto payload_size = std::min(input.size() - i, block.size() - 11);
        std::copy_n(input.cbegin() + i, payload_size, block.end() - payload_size);
        block.at(1) = 2;
        for (size_t j = 2; j < block.size() - payload_size - 1; ++j)
        {
            block.at(j) = j; // this padding should be random
        }
        const auto cypher_block = rsa_compute(BigNumber(block), public_key, modulus)
                .data();
        output.insert(output.cend(), cypher_block.begin(), cypher_block.end());
        std::fill(block.begin(), block.end(), 0);
        i += payload_size;
    }
    return output;
}

std::vector<unsigned char> rsa_decrypt(
        const std::vector<unsigned char> &cypher,
        const BigNumber &private_key,
        const BigNumber &modulus)
{
    if (modulus.bit_length() % 8 != 0)
    {
        throw std::runtime_error("modulus bit length must be multiple of 8");
    }
    std::vector<unsigned char> output{};
    std::vector<unsigned char> cypher_block(modulus.bit_length() / 8, 0);
    if (cypher.size() % (modulus.bit_length() / 8) != 0)
    {
        throw std::runtime_error("mailformed cypher");
    }
    for (size_t i = 0; i < cypher.size(); i += cypher_block.size())
    {
        std::copy_n(cypher.begin() + i, cypher_block.size(), cypher_block.begin());
        const auto decrypted_block = rsa_compute(BigNumber(cypher_block), private_key, modulus).data();
        if (decrypted_block.at(1) != 2)
        {
            throw std::runtime_error("unexpected padding type");
        }
        auto payload_start = decrypted_block.begin() + 2;
        while (payload_start != decrypted_block.end() && *payload_start++ != 0);
        if (payload_start == decrypted_block.end())
        {
            throw std::runtime_error("Failed to obtain payload");
        }
        std::copy(payload_start, decrypted_block.end(), std::back_inserter(output));
    }
    return output;
}