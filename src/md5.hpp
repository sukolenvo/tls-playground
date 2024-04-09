
#ifndef TLS_PLAYGROUND_MD5_HPP
#define TLS_PLAYGROUND_MD5_HPP

#include <array>
#include <vector>

std::array<unsigned char, 16> md5_hash(const std::vector<unsigned char> &input);

class Md5Hashing
{
	std::array<uint_fast32_t, 4> state;
	std::array<unsigned char, 64> block_buffer{};
	size_t buffer_pos{};
	size_t input_size{};
public:
	Md5Hashing();
	void append(const std::vector<unsigned char>&input);
	std::array<unsigned char, 16> close();
};


#endif //TLS_PLAYGROUND_MD5_HPP
