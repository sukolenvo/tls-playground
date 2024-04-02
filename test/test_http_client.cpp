#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <tuple>

#include "http_client.hpp"

TEST_CASE("get from local server")
{
	const auto result = http_get("http://localhost:8000/config.txt");
	CAPTURE(std::string(result.begin(), result.end()));
	const auto expected_prefix = std::string{"HTTP/1.0 200 OK"};
	REQUIRE(result.size() > expected_prefix.size());
	REQUIRE(std::string(result.begin(), result.begin() + expected_prefix.size()) == expected_prefix);
}

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