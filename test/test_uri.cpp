#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <tuple>

#include "uri.hpp"

TEST_CASE("parse_url")
{
	const auto task = GENERATE(
			std::make_pair("https://test.com:8080/test", Uri{ "https", "test.com", { 8080 }, "/test" }),
			std::make_pair("https://test.com:8080", Uri{ "https", "test.com", { 8080 }, "/" }),
			std::make_pair("https://test.com", Uri{ "https", "test.com", {}, "/" }),
			std::make_pair("jdbc:postgresql://test.com/test", Uri{ "jdbc:postgresql", "test.com", {}, "/test" }),
			std::make_pair("https://test.com/", Uri{ "https", "test.com", {}, "/" })
	);

	CAPTURE(task.first);
	REQUIRE(parse_url(task.first) == task.second);
}