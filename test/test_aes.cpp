#include <array>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "aes.hpp"

TEST_CASE("column_mixing")
{
	auto input = std::array<std::array<unsigned char, 4>, 4>{
			std::array<unsigned char, 4>{
					0x87, 0xf2, 0x4d, 0x97
			},
			{
					0x6e, 0x4c, 0x90, 0xec
			},
			{
					0x46, 0xe7, 0x4a, 0xc3
			},
			{
					0xa6, 0x8c, 0xd8, 0x95
			},
	};

	const auto expected = std::array<std::array<unsigned char, 4>, 4>{
			std::array<unsigned char, 4>{
					0x47, 0x40, 0xa3, 0x4c
			},
			{
					0x37, 0x4d, 0x70, 0x9f
			},
			{
					0x94, 0xe4, 0x3a, 0x42
			},
			{
					0xed, 0xa5, 0xa6, 0xbc
			},
	};
	mix_column(input);

	REQUIRE(input == expected);
}