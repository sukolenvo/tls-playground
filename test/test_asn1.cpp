#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "utils.hpp"
#include "asn1.hpp"

TEST_CASE("parse ASN.1")
{
	const auto file_data = read_file("resources/cert.der");
	const std::vector<unsigned char> data{ file_data.begin(), file_data.end() };
	const auto result = parse_asn1(data);
	REQUIRE(result.type == Asn1Type::Sequence);
}

TEST_CASE("get_by_asn_path")
{
	const auto file_data = read_file("resources/cert.der");
	const std::vector<unsigned char> data{ file_data.begin(), file_data.end() };
	const auto result = get_by_asn_path(data, { 0, 4, 0 }); // validity
	REQUIRE(result ==
			std::vector<unsigned char>{ '2', '4', '0', '3', '2', '8', '1', '9', '1', '6', '2', '6', 'Z' });
}