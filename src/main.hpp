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

static void permute(std::vector<unsigned char> &target, std::vector<unsigned char> &src, std::vector<unsigned int> permute_table) {
    if (permute_table.size() * 8 != target.size()) {
        throw std::runtime_error("permute table size doesn't match target size");
    }
    if (src.size() > target.size()) {
        throw std::runtime_error("unexpected source size");
    }
    for (int i = 0; i < src.size() * 8; ++i) {
        if (get_bit(src.cbegin(), permute_table.at(i))) {
            set_bit(target, i);
        } else {
            clear_bit(target, i);
        }
    }
}

#endif //TLS_PLAYGROUND_MAIN_HPP
