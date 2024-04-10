#ifndef TLS_PLAYGROUND_HMAC_HPP
#define TLS_PLAYGROUND_HMAC_HPP

#include <array>
#include <vector>

[[nodiscard]]
std::array<unsigned char, 32> hmac_sha256(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key);

[[nodiscard]]
std::array<unsigned char, 20> hmac_sha1(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key);

[[nodiscard]]
std::array<unsigned char, 16> hmac_md5(
		const std::vector<unsigned char> &input,
		const std::vector<unsigned char> &key);

#endif //TLS_PLAYGROUND_HMAC_HPP
