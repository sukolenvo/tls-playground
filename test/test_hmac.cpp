#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <utility>

#include "utils.hpp"
#include "hmac.hpp"

TEST_CASE("hmac_sha256")
{
	auto task = GENERATE(
			std::make_tuple(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
					std::vector<unsigned char>{'p', 'a', 's', 's'},
					"e39badc5c526435ece43fdb73f31d0ac92e1d1fd2b0d9c0325c8fbda4e348e49")
	);

	CAPTURE(std::get<0>(task));
	const auto result = hmac_sha256(std::get<0>(task), std::get<1>(task));
	REQUIRE(hexStr(result.begin(), result.end()) == std::get<2>(task));
}