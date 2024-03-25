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
	REQUIRE(result - BigNumber(std::get<1>(task)) == BigNumber(std::get<0>(task)));
	REQUIRE(result - BigNumber(std::get<0>(task)) == BigNumber(std::get<1>(task)));
}

TEST_CASE("add_signed")
{
	auto task =
			GENERATE(
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0xFF }, Sign::PLUS),
							BigNumber(std::vector<unsigned char>{ 0xFF }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{})),
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::PLUS),
							BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::MINUS)),
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::PLUS),
							BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::PLUS)),
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::PLUS),
							BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::PLUS)),
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::PLUS),
							BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::MINUS)),
					std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS),
							BigNumber(std::vector<unsigned char>{ 0x07 }, Sign::MINUS))
			);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	auto result = std::get<0>(task) + std::get<1>(task);
	REQUIRE(result == std::get<2>(task));
	REQUIRE(result - std::get<0>(task) == std::get<1>(task));
	REQUIRE(result - std::get<1>(task) == std::get<0>(task));
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
			std::make_tuple(std::vector<unsigned char>{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00 },
					1,
					std::vector<unsigned char>{ 0x01, 0xFD, 0xB9, 0x75, 0x30, 0xEC, 0xA8, 0x64, 0x20, 0x00 }),
			std::make_tuple(std::vector<unsigned char>{ },
					20,
					std::vector<unsigned char>{ }),
			std::make_tuple(std::vector<unsigned char>{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00 },
					17,
					std::vector<unsigned char>{ 0x01, 0xFD, 0xB9, 0x75, 0x30, 0xEC, 0xA8, 0x64, 0x20, 0x00, 0x00, 0x00 })
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	BigNumber value{ std::get<0>(task) };
	value <<= std::get<1>(task);
	REQUIRE(value == BigNumber{ std::get<2>(task) });
}

TEST_CASE("compare")
{
	auto task = GENERATE(
			std::make_tuple(std::vector<unsigned char>{ }, std::vector<unsigned char>{ 0x01 }, true),
			std::make_tuple(std::vector<unsigned char>{ }, std::vector<unsigned char>{ 0x01, 0x00 }, true),
			std::make_tuple(std::vector<unsigned char>{ }, std::vector<unsigned char>{ }, false),
			std::make_tuple(std::vector<unsigned char>{ 0x01 }, std::vector<unsigned char>{ }, false),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0x00 }, std::vector<unsigned char>{ }, false),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0x00 }, std::vector<unsigned char>{ 0x01, 0x00 }, false),
			std::make_tuple(std::vector<unsigned char>{ 0x02, 0x00 }, std::vector<unsigned char>{ 0x01, 0x00 }, false),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0x00 }, std::vector<unsigned char>{ 0x02, 0x00 }, true),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0x10 }, std::vector<unsigned char>{ 0x01, 0x20 }, true),
			std::make_tuple(std::vector<unsigned char>{ 0xFF }, std::vector<unsigned char>{ 0x01, 0x00 }, true)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	BigNumber first{ std::get<0>(task) };
	BigNumber second{ std::get<1>(task) };
	REQUIRE((first < second) == std::get<2>(task));
	if (std::get<2>(task))
	{
		REQUIRE((first > second) == false);
	}
}

TEST_CASE("compare_sign")
{
	auto task = GENERATE(
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x01 }, Sign::PLUS), BigNumber(std::vector<unsigned char>{ }, Sign::PLUS), false),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x01 }, Sign::PLUS), BigNumber(std::vector<unsigned char>{ }, Sign::MINUS), false),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x01 }, Sign::MINUS), BigNumber(std::vector<unsigned char>{ }, Sign::PLUS), true),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x01 }, Sign::MINUS), BigNumber(std::vector<unsigned char>{ }, Sign::MINUS), true),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS), BigNumber(std::vector<unsigned char>{ 0x01 }, Sign::MINUS), true),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS), BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::MINUS), false),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::MINUS), BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::PLUS), true),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x02 }, Sign::PLUS), BigNumber(std::vector<unsigned char>{ 0x03 }, Sign::MINUS), false)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	REQUIRE((std::get<0>(task) < std::get<1>(task)) == std::get<2>(task));
}


TEST_CASE("modulus")
{
	auto task = GENERATE(
			std::make_tuple(std::vector<unsigned char>{ }, std::vector<unsigned char>{}, std::vector<unsigned char>{}),
			std::make_tuple(std::vector<unsigned char>{ }, std::vector<unsigned char>{ 0x01}, std::vector<unsigned char>{}),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0xFD, 0xB9, 0x75, 0x30, 0xEC, 0xA8, 0x64, 0x20, 0x00, 0x00, 0x00 },
					std::vector<unsigned char>{ 0x01}, std::vector<unsigned char>{}),
			std::make_tuple(std::vector<unsigned char>{ 0x01, 0xFD, 0xB9, 0x75, 0x30, 0xEC, 0xA8, 0x64, 0x20, 0x00, 0x00, 0x00 }, std::vector<unsigned char>{ 0x02},
					std::vector<unsigned char>{}),
			std::make_tuple(std::vector<unsigned char>{ 0x1E, 0x92, 0xA6, 0x91 }, // 512927377
					std::vector<unsigned char>{ 0x01, 0xEF, 0x30, 0xEB}, // 32452843
					std::vector<unsigned char>{ 0x01, 0x8E, 0xC8, 0xCC }) // 26134732
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	const BigNumber first{ std::get<0>(task) };
	const BigNumber second{ std::get<1>(task) };
	REQUIRE(first % second == BigNumber(std::get<2>(task)));
}

TEST_CASE("modulus signed")
{
	auto task = GENERATE(
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x11 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x07 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x04 }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x11 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x07 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x04 }, Sign::PLUS)
			)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task) % std::get<1>(task) == std::get<2>(task));
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

TEST_CASE("multiply signed")
{
	auto task = GENERATE(
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x2 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x3 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x6 }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x2 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x3 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x6 }, Sign::MINUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x2 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x3 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x6 }, Sign::PLUS)
			)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task) * std::get<1>(task) == std::get<2>(task));
	REQUIRE(std::get<1>(task) * std::get<0>(task) == std::get<2>(task));
}

TEST_CASE("bit_length")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{  }, 0),
			std::make_pair(std::vector<unsigned char>{ 0x01 }, 1),
			std::make_pair(std::vector<unsigned char>{ 0x02 }, 2),
			std::make_pair(std::vector<unsigned char>{ 0x03 }, 2),
			std::make_pair(std::vector<unsigned char>{ 0x04 }, 3),
			std::make_pair(std::vector<unsigned char>{ 0x08 }, 4),
			std::make_pair(std::vector<unsigned char>{ 0x0F }, 4),
			std::make_pair(std::vector<unsigned char>{ 0x10 }, 5),
			std::make_pair(std::vector<unsigned char>{ 0x11 }, 5),
			std::make_pair(std::vector<unsigned char>{ 0x21 }, 6),
			std::make_pair(std::vector<unsigned char>{ 0x41 }, 7),
			std::make_pair(std::vector<unsigned char>{ 0x80 }, 8),
			std::make_pair(std::vector<unsigned char>{ 0xFF }, 8),
			std::make_pair(std::vector<unsigned char>{ 0x0F, 0x0, 0x0 }, 20)
	);
	CAPTURE(std::get<0>(task));
	REQUIRE(BigNumber{ std::get<0>(task)}.bit_length() == std::get<1>(task));
}

TEST_CASE("divide")
{
	auto task = GENERATE(
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x14 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x05 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x04 }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x15 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x5 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x4 }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0xA }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x5 }, Sign::MINUS),
					BigNumber(std::vector<unsigned char>{ 0x2 }, Sign::MINUS)
			)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task) / std::get<1>(task) == std::get<2>(task));
	REQUIRE(std::get<0>(task) / std::get<2>(task) == std::get<1>(task));
}

TEST_CASE("inverse_multiplicative")
{
	auto task = GENERATE(
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x5 }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x0D }, Sign::PLUS),
					BigNumber(std::vector<unsigned char>{ 0x08 }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x25 }, Sign::PLUS), // 37
					BigNumber(std::vector<unsigned char>{ 0x66 }, Sign::PLUS), // 102
					BigNumber(std::vector<unsigned char>{ 0x5B }, Sign::PLUS)
			),
			std::make_tuple(BigNumber(std::vector<unsigned char>{ 0x01, 0x7F }, Sign::PLUS), // 383
					BigNumber(std::vector<unsigned char>{ 0x07, 0x7A }, Sign::PLUS), // 1914
					BigNumber(std::vector<unsigned char>{ 0x5 }, Sign::PLUS)
			)
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task).inverse_multiplicative(std::get<1>(task)) == std::get<2>(task));
}