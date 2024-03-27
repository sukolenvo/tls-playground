#ifndef TLS_PLAYGROUND_DSA_HPP
#define TLS_PLAYGROUND_DSA_HPP

#include "math.hpp"

[[nodiscard]]
BigNumber dsa_message_hash_sha256(const std::vector<unsigned char> &message, const BigNumber &q);

[[nodiscard]]
BigNumber generate_secret(const BigNumber &q);

struct DsaSignature
{
	BigNumber r;
	BigNumber s;
};

class Dsa
{
	BigNumber g, p, q;

public:
	Dsa(BigNumber g, BigNumber p, BigNumber q);

	[[nodiscard]]
	DsaSignature sign_sha256(const std::vector<unsigned char> &message, const BigNumber &private_key) const;

	[[nodiscard]]
	bool verify_sha256(const std::vector<unsigned char> &message,
			const DsaSignature &signature,
			const BigNumber &public_key) const;
};

#endif //TLS_PLAYGROUND_DSA_HPP
