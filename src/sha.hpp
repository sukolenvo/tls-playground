#ifndef TLS_PLAYGROUND_SHA_HPP
#define TLS_PLAYGROUND_SHA_HPP

#include <array>
#include <vector>

std::array<unsigned char, 20> sha1_hash(const std::vector<unsigned char> &input);

#endif //TLS_PLAYGROUND_SHA_HPP
