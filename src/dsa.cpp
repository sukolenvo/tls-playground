#include "sha.hpp"
#include "dsa.hpp"

#include <utility>

BigNumber Dsa::generate_message_secret() const
{
	std::vector<unsigned char> c(q.bit_length() / 8 + 1);
	for (size_t i = 0; i < c.size(); ++i)
	{
		c[i] = i + 1;
	}
	return BigNumber(c) % (q - BigNumber({ 1 })) + BigNumber({ 1 });
}

DsaSignature Dsa::sign_sha256(const std::vector<unsigned char> &message, const BigNumber &private_key) const
{
	const auto message_hash = sha256_hash(message);
	const BigNumber z({ message_hash.begin(), message_hash.end() });

	const auto k = generate_message_secret();
	const auto r = g.power_modulus(k, p) % q;
	const auto s = k.inverse_multiplicative(q) * (r * private_key + z) % q;
	return { r, s };
}

bool Dsa::verify_sha256(const std::vector<unsigned char> &message,
		const DsaSignature &signature,
		const BigNumber &public_key) const
{
	const auto w = signature.s.inverse_multiplicative(q);
	const auto message_hash = sha256_hash(message);
	const BigNumber z({ message_hash.begin(), message_hash.end() });
	const auto u1 = z * w % q;
	const auto u2 = signature.r * w % q;
	const auto v = (g.power_modulus(u1, p) * public_key.power_modulus(u2, p)) % p % q;
	return v == signature.r;
}

Dsa::Dsa(BigNumber g, BigNumber p, BigNumber q) : g(std::move(g)), p(std::move(p)), q(std::move(q))
{

}
