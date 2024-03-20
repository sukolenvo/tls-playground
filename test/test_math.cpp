#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "math.hpp"

TEST_CASE("add")
{
	auto task = GENERATE(
			std::make_tuple(std::vector<unsigned char>{ 0xFF }, std::vector<unsigned char>{ },
					std::vector<unsigned char>{ 0xFF }),
			std::make_tuple(std::vector<unsigned char>{  }, std::vector<unsigned char>{ 0x7 },
					std::vector<unsigned char>{ 0x7 }),
			std::make_tuple(std::vector<unsigned char>{ 0xFF, 0xFF, 0xFF, 0xFF }, std::vector<unsigned char>{ 0x1 },
					std::vector<unsigned char>{ 0x01, 0x00, 0x00, 0x00, 0x00 }),
			std::make_tuple(std::vector<unsigned char>{ 0x1, 0x2, }, std::vector<unsigned char>{ 0x02, 0x3, 0x4, 0x5 },
					std::vector<unsigned char>{ 0x02, 0x3, 0x5, 0x7 }),
			std::make_tuple(std::vector<unsigned char>{ 0xF0, }, std::vector<unsigned char>{ 0x10 },
					std::vector<unsigned char>{ 0x01, 0x00 })
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	auto result = BigNumber(std::get<0>(task)) + BigNumber(std::get<1>(task));
	REQUIRE(result == BigNumber(std::get<2>(task)));
}

TEST_CASE("subtract")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{  }, std::vector<unsigned char>{ }),
			std::make_pair(std::vector<unsigned char>{ 0x07 }, std::vector<unsigned char>{ }),
			std::make_pair(std::vector<unsigned char>{ 0xFF, 0xFF, 0xFF, 0xFF }, std::vector<unsigned char>{ 0x1 }),
			std::make_pair(std::vector<unsigned char>{ 0x1, 0x2, }, std::vector<unsigned char>{ 0x02, 0x3, 0x4, 0x5 }),
			std::make_pair(std::vector<unsigned char>{ 0xF0, }, std::vector<unsigned char>{ 0x10 })
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	auto sum = BigNumber(std::get<0>(task)) + BigNumber(std::get<1>(task));
	REQUIRE(sum - BigNumber(std::get<0>(task)) == BigNumber(std::get<1>(task)));
	REQUIRE(sum - BigNumber(std::get<1>(task)) == BigNumber(std::get<0>(task)));
}

TEST_CASE("shift left assign")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00 },
					std::vector<unsigned char>{ 0x01, 0xFD, 0xB9, 0x75,0x30, 0xEC, 0xA8, 0x64, 0x20, 0x00 })
	);
	CAPTURE(std::get<0>(task));
	BigNumber value{std::get<0>(task)};
	value <<= 1;
	REQUIRE(value == BigNumber{std::get<1>(task)});
}

TEST_CASE("multiply")
{
	auto task = GENERATE(
			std::make_tuple(std::vector<unsigned char>{ 0x0A, 0x3F, 0x87 }, // 671623
					std::vector<unsigned char>{ 0x4a, 0x07 }, // 18951
					std::vector<unsigned char>{ 0x02, 0xf6, 0xa4, 0xc2, 0xb1 } // 12727927473
			)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	auto result = BigNumber{ std::get<0>(task)} * BigNumber{std::get<1>(task)};
	REQUIRE(result == BigNumber{ std::get<2>(task) });
}
