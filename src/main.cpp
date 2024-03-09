#include <iostream>
#include <stdexcept>
#include <vector>

#include "main.hpp"

bool get_bit(const std::vector<unsigned char>::const_iterator &src, unsigned int index) {
    if (index > 64) {
        throw std::runtime_error("index is out of range");
    }
    return *(src + (index - 1) / 8) & (0x80 >> ((index - 1) % 8));
}