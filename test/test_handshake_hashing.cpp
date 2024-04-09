#include <catch2/catch_test_macros.hpp>

#include "utils.hpp"
#include "handshake_hashing.hpp"

TEST_CASE("handhshake hashing")
{
	const std::vector<unsigned char> master_secret(48, 8);
	HandshakeHashing hashing{};
	hashing.append({1, 2,3});
	hashing.append(std::vector<char>(777, 7));
	const auto client_hash = hashing.compute_finished_hash(master_secret, "client finished");
	const auto server_hash = hashing.compute_finished_hash(master_secret, "server finished");
	REQUIRE(hexStr(client_hash.begin(), client_hash.end()) == "f772ea32b1807da5978400a4");
	REQUIRE(hexStr(server_hash.begin(), server_hash.end()) == "e72c0fd6c85080edac03136c");
}