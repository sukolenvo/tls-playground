#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "http_client.hpp"

TEST_CASE("get from local server")
{
    const auto result = http_get("http://localhost:8080/config.txt");
    CAPTURE(std::string(result.begin(), result.end()));
    const auto expected_prefix = std::string{ "HTTP/1.0 200 OK" };
    REQUIRE(result.size() > expected_prefix.size());
    REQUIRE(std::string(result.begin(), result.begin() + expected_prefix.size()) == expected_prefix);
}

TEST_CASE("get from google")
{
    const auto result = http_get("https://www.google.com");
    CAPTURE(std::string(result.begin(), result.end()));
    const auto expected_prefix = std::string{ "HTTP/1.1 200 OK" };
    REQUIRE(result.size() > expected_prefix.size());
    REQUIRE(std::string(result.begin(), result.begin() + expected_prefix.size()) == expected_prefix);
}