//
// Created by Margo on 09.03.2024.
//

#ifndef TLS_PLAYGROUND_MAIN_HPP
#define TLS_PLAYGROUND_MAIN_HPP

#include <stdexcept>
#include <vector>

/**
 * Get big endian bit from array.
 * @param index [1..64]
 */
bool get_bit(const std::vector<unsigned char>::const_iterator &src, unsigned int index);

constexpr void permute(std::vector<char> &target, std::vector<char> &src, std::vector<char> permute_table) {
    if (permute_table.size() * 8 != target.size()) {
        throw std::runtime_error("permute table size doesn't match target size");
    }

}

#endif //TLS_PLAYGROUND_MAIN_HPP
