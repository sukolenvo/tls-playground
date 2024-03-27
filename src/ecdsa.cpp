#include "ecc.hpp"
#include "dsa.hpp"
#include "ecdsa.hpp"

DsaSignature EcDsa::sign(
		const std::vector<unsigned char> &message,
		const BigNumber &private_key) const
{
	BigPoint x = curve.multiply_point(generator, k);

	const auto r = x.x % q;

	const auto z = dsa_message_hash_sha256(message, q);

	const auto s = k.inverse_multiplicative(q) * (private_key * r + z) % q;
	return { r, s };
}

bool EcDsa::verify(const std::vector<unsigned char> &message,
		const DsaSignature &signature,
		const BigPoint &public_key) const
{
	const auto w = signature.s.inverse_multiplicative(q);
	const auto z = dsa_message_hash_sha256(message, q);
	const auto u1 = z * w % q;
	const auto u2 = signature.r * w % q;
	const auto x1 = curve.multiply_point(generator, u1);
	const auto x2 = curve.multiply_point(public_key, u2);
	const auto expected_r = curve.sum_points(x1, x2).x % q;
	return expected_r == signature.r;
}

EcDsa::EcDsa(BigNumber q, BigPoint generator, EllipticCurve curve) : EcDsa(
		std::move(q),
		generate_secret(q),
		std::move(generator),
		std::move(curve))
{

}

EcDsa::EcDsa(BigNumber q, BigNumber k, BigPoint generator, EllipticCurve curve) : q(std::move(q)),
																				  k(std::move(k)),
																				  generator(std::move(generator)),
																				  curve(std::move(curve))
{

}
