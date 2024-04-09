#ifndef TLS_PLAYGROUND_HANDSHAKE_HASHING_HPP
#define TLS_PLAYGROUND_HANDSHAKE_HASHING_HPP

#include <string>
#include <vector>

#include "md5.hpp"
#include "sha.hpp"

class HandshakeHashing
{
	Md5Hashing md5_hashing{};
	Sha1Hashing sha1_hashing{};
public:
	void append(const std::vector<char> &handshake_message);
	[[nodiscard]]
	std::vector<unsigned char> compute_finished_hash(
			const std::vector<unsigned char> &master_secret,
			const std::string &label) const;
};

#endif //TLS_PLAYGROUND_HANDSHAKE_HASHING_HPP
