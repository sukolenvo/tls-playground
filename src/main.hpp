//
// Created by Margo on 09.03.2024.
//

#ifndef TLS_PLAYGROUND_MAIN_HPP
#define TLS_PLAYGROUND_MAIN_HPP

#include <array>
#include <stdexcept>
#include <vector>

/**
 * Get big endian bit from the src.
 *
 * @param index [1..64]
 */
[[nodiscard]]
bool get_bit(const std::vector<unsigned char>::const_iterator &src, unsigned int index);

/**
 * Set big endian bit to 1.
 *
 * @param index [1..64]
 */
void set_bit(std::vector<unsigned char> &src, unsigned int index);

/**
 * Set big endian bit to 0.
 *
 * @param index [1..64]
 */
void clear_bit(std::vector<unsigned char> &src, unsigned int index);

const auto initial_permute_table = std::vector<unsigned int>{
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

const auto invert_permute_table = std::vector<unsigned int> {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

void permute(std::vector<unsigned char> &target, std::vector<unsigned char> &src, std::vector<unsigned int> permute_table);

void schedule_key_rotl(std::array<unsigned char, 7> &key);

#endif //TLS_PLAYGROUND_MAIN_HPP
