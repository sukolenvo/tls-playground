#ifndef TLS_PLAYGROUND_SHA_HPP
#define TLS_PLAYGROUND_SHA_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

std::array<unsigned char, 32> sha256_hash(const std::vector<unsigned char> &input);

class Sha1Hashing
{
    std::array<uint_fast32_t, 5> state;
    std::array<unsigned char, 64> block_buffer{};
    size_t buffer_pos{};
    size_t input_size{};
public:
    Sha1Hashing();

    void append(const std::vector<unsigned char> &input);

    std::array<unsigned char, 20> close();
};

#endif //TLS_PLAYGROUND_SHA_HPP
