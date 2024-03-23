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
					"da39a3ee5e6b4b0d3255bfef95601890afd80709"),
			std::make_pair(std::vector<unsigned char>(100, 'a'),
					"7f9000257a4918d7072655ea468540cdcbd42e0c")
	);

	CAPTURE(task.first);
	const auto result = sha1_hash(task.first);
	REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}

TEST_CASE("sha256_hash")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
					"7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"),
			std::make_pair(std::vector<unsigned char>{},
					"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
			std::make_pair(std::vector<unsigned char>(100, 'a'),
					"2816597888e4a0d3a36b82b83316ab32680eb8f00f8cd3b904d681246d285a0e")
	);

	CAPTURE(task.first);
	const auto result = sha256_hash(task.first);
	REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}