#include <algorithm>
#include <array>
#include <cstddef>
#include <stdexcept>
#include <vector>

#include "aes.hpp"

using State = std::array<std::array<unsigned char, 4>, 4>;

const std::array<std::array<unsigned char, 16>, 16> sbox
        {{
                 { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
                   0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76 },
                 { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
                   0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0 },
                 { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
                   0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15 },
                 { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
                   0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75 },
                 { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
                   0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84 },
                 { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
                   0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf },
                 { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
                   0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8 },
                 { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
                   0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2 },
                 { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
                   0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73 },
                 { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
                   0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb },
                 { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
                   0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79 },
                 { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
                   0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08 },
                 { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
                   0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a },
                 { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
                   0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e },
                 { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
                   0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf },
                 { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
                   0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 },
         }};

const std::array<std::array<unsigned char, 16>, 16> decrypt_sbox
        {{
                 { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
                   0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb },
                 { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
                   0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb },
                 { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
                   0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e },
                 { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
                   0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 },
                 { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
                   0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92 },
                 { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
                   0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 },
                 { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
                   0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06 },
                 { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
                   0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b },
                 { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
                   0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73 },
                 { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
                   0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e },
                 { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
                   0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b },
                 { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
                   0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4 },
                 { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
                   0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f },
                 { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
                   0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef },
                 { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
                   0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 },
                 { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
                   0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }
         }};


void substitute_state(State &state)
{
    for (size_t i = 0; i < state.size(); ++i)
    {
        for (size_t j = 0; j < state.at(i).size(); ++j)
        {
            state.at(i).at(j) = sbox.at((state.at(i).at(j) & 0xF0) >> 4).at(state.at(i).at(j) & 0x0F);
        }
    }
}

void unsubstitute_state(State &state)
{
    for (size_t i = 0; i < state.size(); ++i)
    {
        for (size_t j = 0; j < state.at(i).size(); ++j)
        {
            state.at(i).at(j) = decrypt_sbox.at((state.at(i).at(j) & 0xF0) >> 4).at(state.at(i).at(j) & 0x0F);
        }
    }
}

template<size_t key_length, size_t rounds = key_length / 4 + 6>
std::array<State, rounds + 1> build_schedule_key(const std::array<unsigned char, key_length> &key)
{
    std::array<std::array<unsigned char, 4>, (rounds + 1) * 4> buffer{};
    for (size_t i = 0; i < key_length; i += 4)
    {
        buffer.at(i / 4) = { key[i], key[i + 1], key[i + 2], key[i + 3] };
    }
    unsigned char xor_constant = 0x01;
    for (size_t i = key_length / 4; i < buffer.size(); ++i)
    {
        buffer[i] = buffer[i - 1];
        if (i % (key_length / 4) == 0)
        {
            std::swap(buffer[i][0], buffer[i][1]);
            std::swap(buffer[i][1], buffer[i][2]);
            std::swap(buffer[i][2], buffer[i][3]);
            for (auto &item: buffer[i])
            {
                item = sbox.at((item & 0xF0) >> 4).at(item & 0x0F);
            }
            buffer[i][0] ^= xor_constant;
            xor_constant <<= 1;
            if (xor_constant == 0)
            {
                xor_constant = 0x1b;
            }
        }
        else if (key_length == 32 && i % 4 == 0)
        {
            for (auto &item: buffer[i])
            {
                item = sbox.at((item & 0xF0) >> 4).at(item & 0x0F);
            }
        }
        buffer[i][0] ^= buffer[i - key_length / 4][0];
        buffer[i][1] ^= buffer[i - key_length / 4][1];
        buffer[i][2] ^= buffer[i - key_length / 4][2];
        buffer[i][3] ^= buffer[i - key_length / 4][3];
    }
    std::array<State, rounds + 1> result{};
    for (size_t i = 0; i < result.size(); ++i)
    {
        result.at(i).at(0) = buffer.at(i * 4);
        result.at(i).at(1) = buffer.at(i * 4 + 1);
        result.at(i).at(2) = buffer.at(i * 4 + 2);
        result.at(i).at(3) = buffer.at(i * 4 + 3);
    }
    return result;
}

void xor_state(State &state, const State &other)
{
    for (size_t i = 0; i < state.size(); ++i)
    {
        for (size_t j = 0; j < state.at(i).size(); ++j)
        {
            state.at(i).at(j) ^= other.at(i).at(j);
        }
    }
}

unsigned char mul(unsigned char left, unsigned char right)
{
    unsigned char result{};
    for (unsigned char mask = 0x01; mask <= right && mask != 0; mask <<= 1)
    {
        if ((right & mask) != 0)
        {
            result ^= left;
        }
        left = (left << 1) ^ (left & 0x80 ? 0x1b : 0);
    }
    return result;
}

const auto multiplication_matrix = State{{
                                                 { 2, 3, 1, 1 },
                                                 { 1, 2, 3, 1 },
                                                 { 1, 1, 2, 3 },
                                                 { 3, 1, 1, 2 }
                                         }};
const auto unmultiplication_matrix = State{{
                                                   { 0x0e, 0x0b, 0x0d, 0x09 },
                                                   { 0x09, 0x0e, 0x0b, 0x0d },
                                                   { 0x0d, 0x09, 0x0e, 0x0b },
                                                   { 0x0b, 0x0d, 0x09, 0x0e }
                                           }};

void mix_columns(State &state, const State &matrix)
{
    for (size_t i = 0; i < state.size(); ++i)
    {
        const auto c0 = mul(matrix.at(0).at(0), state.at(i).at(0))
                        ^ mul(matrix.at(0).at(1), state.at(i).at(1))
                        ^ mul(matrix.at(0).at(2), state.at(i).at(2))
                        ^ mul(matrix.at(0).at(3), state.at(i).at(3));
        const auto c1 = mul(matrix.at(1).at(0), state.at(i).at(0))
                        ^ mul(matrix.at(1).at(1), state.at(i).at(1))
                        ^ mul(matrix.at(1).at(2), state.at(i).at(2))
                        ^ mul(matrix.at(1).at(3), state.at(i).at(3));
        const auto c2 = mul(matrix.at(2).at(0), state.at(i).at(0))
                        ^ mul(matrix.at(2).at(1), state.at(i).at(1))
                        ^ mul(matrix.at(2).at(2), state.at(i).at(2))
                        ^ mul(matrix.at(2).at(3), state.at(i).at(3));
        const auto c3 = mul(matrix.at(3).at(0), state.at(i).at(0))
                        ^ mul(matrix.at(3).at(1), state.at(i).at(1))
                        ^ mul(matrix.at(3).at(2), state.at(i).at(2))
                        ^ mul(matrix.at(3).at(3), state.at(i).at(3));
        state.at(i).at(0) = c0;
        state.at(i).at(1) = c1;
        state.at(i).at(2) = c2;
        state.at(i).at(3) = c3;
    }
}

void mix_rows(State &state)
{
    // row 0 no-op

    // row 1
    std::swap(state.at(0).at(1), state.at(1).at(1));
    std::swap(state.at(1).at(1), state.at(2).at(1));
    std::swap(state.at(2).at(1), state.at(3).at(1));

    // row 2
    std::swap(state.at(0).at(2), state.at(2).at(2));
    std::swap(state.at(1).at(2), state.at(3).at(2));

    // row 3
    std::swap(state.at(0).at(3), state.at(1).at(3));
    std::swap(state.at(0).at(3), state.at(2).at(3));
    std::swap(state.at(0).at(3), state.at(3).at(3));
}

void unmix_rows(State &state)
{
    // row 0 no-op

    // row 1
    std::swap(state.at(0).at(1), state.at(1).at(1));
    std::swap(state.at(0).at(1), state.at(2).at(1));
    std::swap(state.at(0).at(1), state.at(3).at(1));


    // row 2
    std::swap(state.at(0).at(2), state.at(2).at(2));
    std::swap(state.at(1).at(2), state.at(3).at(2));

    // row 3
    std::swap(state.at(0).at(3), state.at(1).at(3));
    std::swap(state.at(1).at(3), state.at(2).at(3));
    std::swap(state.at(2).at(3), state.at(3).at(3));
}

template<int rounds>
void aes_block_encrypt(const std::array<unsigned char, 16> &input_block, std::array<unsigned char, 16> &output_block,
        const std::array<State, rounds + 1> &schedule_keys)
{
    State state{};

    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            state.at(i).at(j) = input_block.at(4 * i + j);
        }
    }
    xor_state(state, schedule_keys.at(0));
    for (int round = 0; round < rounds; ++round)
    {
        substitute_state(state);
        mix_rows(state);
        if (round < rounds - 1)
        {
            mix_columns(state, multiplication_matrix);
        }
        xor_state(state, schedule_keys.at(round + 1));
    }
    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            output_block.at(i * 4 + j) = state.at(i).at(j);
        }
    }
}

template<int rounds>
void aes_block_decrypt(const std::array<unsigned char, 16> &input_block, std::array<unsigned char, 16> &output_block,
        const std::array<State, rounds + 1> &schedule_keys)
{
    State state{};

    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            state.at(i).at(j) = input_block.at(i * 4 + j);
        }
    }
    xor_state(state, schedule_keys.at(rounds));
    for (int round = rounds - 1; round >= 0; --round)
    {
        unmix_rows(state);
        unsubstitute_state(state);
        xor_state(state, schedule_keys.at(round));
        if (round > 0)
        {
            mix_columns(state, unmultiplication_matrix);
        }
    }
    for (size_t i = 0; i < 4; ++i)
    {
        for (size_t j = 0; j < 4; ++j)
        {
            output_block.at(i * 4 + j) = state.at(i).at(j);
        }
    }
}

template<size_t keysize>
std::vector<unsigned char> aes_cbc_encrypt(const std::vector<unsigned char> &input,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, keysize> &key)
{
    if (input.size() % 16 != 0)
    {
        throw std::runtime_error("input should be padded");
    }
    std::vector<unsigned char> result{};
    std::array<unsigned char, 16> input_block;
    std::array<unsigned char, 16> cypher_block = iv;
    const auto schedule_keys = build_schedule_key(key);
    for (size_t i = 0; i < input.size(); i += 16)
    {
        std::copy_n(input.cbegin() + i, 16, input_block.begin());
        std::transform(input_block.begin(), input_block.end(), cypher_block.cbegin(),
                input_block.begin(),
                [](const auto &left, const auto &right)
                {
                    return left ^ right;
                });
        aes_block_encrypt<keysize / 4 + 6>(input_block, cypher_block, schedule_keys);
        std::copy_n(cypher_block.cbegin(), 16, std::back_inserter(result));
    }
    return result;
}

template<size_t keysize>
std::vector<unsigned char> aes_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, keysize> &key)
{
    if (cypher_data.size() % 16 != 0)
    {
        throw std::runtime_error("Malformed cypher data");
    }
    std::vector<unsigned char> result{};
    std::array<unsigned char, 16> input_block;
    std::array<unsigned char, 16> output_block;
    auto next_iv = iv;
    const auto schedule_keys = build_schedule_key(key);
    for (size_t i = 0; i < cypher_data.size(); i += 16)
    {
        std::copy_n(cypher_data.cbegin() + i, 16, input_block.begin());
        aes_block_decrypt<keysize / 4 + 6>(input_block, output_block, schedule_keys);
        std::transform(output_block.begin(), output_block.end(), next_iv.cbegin(),
                output_block.begin(),
                [](const auto &left, const auto &right)
                {
                    return left ^ right;
                });
        next_iv = input_block;
        std::copy_n(output_block.cbegin(), 16, std::back_inserter(result));
    }
    return result;
}

std::vector<unsigned char> aes128_cbc_encrypt(const std::vector<unsigned char> &input,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 16> &key)
{
    return aes_cbc_encrypt(input, iv, key);
}

std::vector<unsigned char> aes128_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 16> &key)
{
    return aes_cbc_decrypt(cypher_data, iv, key);
}

std::vector<unsigned char> aes192_cbc_encrypt(const std::vector<unsigned char> &input,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 24> &key)
{
    return aes_cbc_encrypt(input, iv, key);
}

std::vector<unsigned char> aes192_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 24> &key)
{
    return aes_cbc_decrypt(cypher_data, iv, key);
}

std::vector<unsigned char> aes256_cbc_encrypt(const std::vector<unsigned char> &input,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 32> &key)
{
    return aes_cbc_encrypt(input, iv, key);
}

std::vector<unsigned char> aes256_cbc_decrypt(const std::vector<unsigned char> &cypher_data,
        const std::array<unsigned char, 16> &iv,
        const std::array<unsigned char, 32> &key)
{
    return aes_cbc_decrypt(cypher_data, iv, key);
}