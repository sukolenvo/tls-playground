#include <stdexcept>
#include <vector>

#include "main.hpp"

bool get_bit(const std::vector<unsigned char>::const_iterator &src, unsigned int index) {
    if (index > 64) {
        throw std::runtime_error("index is out of range");
    }
    return *(src + (index - 1) / 8) & (0x80 >> ((index - 1) % 8));
}

void set_bit(std::vector<unsigned char> &src, unsigned int index) {
    auto &item = src.at((index - 1) / 8);
    item |= (0x80 >> (index - 1) % 8);
}

void clear_bit(std::vector<unsigned char> &src, unsigned int index) {
    auto &item = src.at((index - 1) / 8);
    item &= ~(0x80 >> (index - 1) % 8);
}

void permute(std::vector<unsigned char> &target, std::vector<unsigned char> &src, std::vector<unsigned int> permute_table) {
    if (permute_table.size() != target.size() * 8) {
        throw std::runtime_error("permute table size doesn't match target size");
    }
    if (src.size() > target.size()) {
        throw std::runtime_error("unexpected source size");
    }
    for (int i = 0; i < src.size() * 8; ++i) {
        if (get_bit(src.cbegin(), permute_table.at(i))) {
            set_bit(target, i + 1);
        } else {
            clear_bit(target, i + 1);
        }
    }
}
