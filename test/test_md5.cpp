#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <utility>

#include "utils.hpp"
#include "md5.hpp"

TEST_CASE("md5_hash")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
					"ed076287532e86365e841e92bfc50d8c"),
			std::make_pair(std::vector<unsigned char>{}, "d41d8cd98f00b204e9800998ecf8427e"),
			std::make_pair(std::vector<unsigned char>(100, 'a'),
					"36a92cc94a9e0fa21f625f8bfb007adf")
	);

	CAPTURE(task.first);
	const auto result = md5_hash(task.first);
	REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}