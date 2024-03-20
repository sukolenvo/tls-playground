#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "rsa.hpp"

TEST_CASE("compute")
{
	BigNumber message({0x02, 0xB0}); // 688
	BigNumber exp({0x4F}); // 79
	BigNumber modulus({0x0D, 0x09}); // 3337
	BigNumber p_exp({0x03, 0xFB}); // 1019
	const auto encrypted = rsa_compute(message, exp, modulus);
	CAPTURE(encrypted);
	REQUIRE(rsa_compute(encrypted, p_exp, modulus) == message);
}