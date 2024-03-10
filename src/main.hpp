//
// Created by Margo on 09.03.2024.
//

#ifndef TLS_PLAYGROUND_MAIN_HPP
#define TLS_PLAYGROUND_MAIN_HPP

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

void permute(std::vector<unsigned char> &target, std::vector<unsigned char> &src, std::vector<unsigned int> permute_table);

#endif //TLS_PLAYGROUND_MAIN_HPP
