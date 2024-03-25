#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "ecc.hpp"

TEST_CASE("elliptic curve")
{
	EllipticCurve ecc{ BigNumber({ 1 }), BigNumber({ 1 }) };
	BigPoint generator{ BigNumber({ 5 }), BigNumber({ 19 }) };

	const BigNumber modulus({ 23 });

	const BigNumber first_private_key({ 4 });
	const auto first_public_key = ecc.multiply_point(generator, first_private_key, modulus);
	const BigNumber second_private_key({ 2 });
	const auto second_public_key = ecc.multiply_point(generator, second_private_key, modulus);

	const auto first_shared_secret = ecc.multiply_point(second_public_key, first_private_key, modulus);
	const auto second_shared_secret = ecc.multiply_point(first_public_key, second_private_key, modulus);
	REQUIRE(first_shared_secret == second_shared_secret);
}