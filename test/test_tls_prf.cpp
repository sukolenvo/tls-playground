#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils.hpp"
#include "tls_prf.hpp"

TEST_CASE("tls prf")
{
	std::vector<unsigned char> out(40);
	prf({ 'a', 'b' }, { 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l' }, out);
	REQUIRE(hexStr(out.begin(), out.end()) ==
			"f73d398ae7b65c1cb45ca30d10ab6b8e7660d01cc8f4c8b3f857963fe773ec32740eb07dfea41ca7");
}

TEST_CASE("compute master secret")
{
	std::array<unsigned char, 48> premaster{ 3, 1, 33 };
	std::array<unsigned char, 32> client_random{ 0x66, 0x12, 0x4b, 0x36 };
	std::array<unsigned char, 32> server_random{ 0x66, 0x12, 0x90, 0x5c, 0x38, 0x30, 0x37, 0xae, 0x38, 0x92, 0x18, 0x4f,
												 0xd4, 0xcb, 0x06, 0xf4, 0xbe, 0x1b, 0xc7, 0x03, 0x6b, 0x05, 0x5d, 0xa9,
												 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00 };
	const auto master_secret = compute_master_secret(premaster, client_random, server_random);
	REQUIRE(hexStr(master_secret.begin(), master_secret.end()) == "e2a0eb98d54dbcf76c5c7f6ead53faabaefdead59e2b2ffb219a24854c96c9c19d521ff9ee01b9bcd4093f004915acfe");
}