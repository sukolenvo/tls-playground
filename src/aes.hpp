#ifndef TLS_PLAYGROUND_AES_HPP
#define TLS_PLAYGROUND_AES_HPP

#include <array>

void mix_column(std::array<std::array<unsigned char, 4>, 4> &state);

#endif //TLS_PLAYGROUND_AES_HPP
