#ifndef TLS_PLAYGROUND_TLS_PRF_HPP
#define TLS_PLAYGROUND_TLS_PRF_HPP

#include <vector>

std::vector<unsigned char> prf(const std::vector<unsigned char> &secret, const std::vector<unsigned char> &seed);

#endif //TLS_PLAYGROUND_TLS_PRF_HPP
