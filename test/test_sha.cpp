#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <utility>

#include "utils.hpp"
#include "sha.hpp"

TEST_CASE("sha1_hash")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
					"2ef7bde608ce5404e97d5f042f95f89f1c232871"),
			std::make_pair(std::vector<unsigned char>{},
					"da39a3ee5e6b4b0d3255bfef95601890afd80709")
	);

	CAPTURE(task.first);
	const auto result = sha1_hash(task.first);
	REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}