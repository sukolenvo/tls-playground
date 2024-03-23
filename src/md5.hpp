
#ifndef TLS_PLAYGROUND_MD5_HPP
#define TLS_PLAYGROUND_MD5_HPP

#include <array>
#include <vector>

std::array<unsigned char, 16> md5_hash(const std::vector<unsigned char> &input);

#endif //TLS_PLAYGROUND_MD5_HPP
