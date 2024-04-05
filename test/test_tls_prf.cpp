#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils.hpp"
#include "tls_prf.hpp"

TEST_CASE("tls prf")
{
	const auto result = prf({'a', 'b'}, {'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'});
	REQUIRE(hexStr(result.begin(), result.end()) == "f73d398ae7b65c1cb45ca30d10ab6b8e7660d01cc8f4c8b3f857963fe773ec32740eb07dfea41ca7");
}