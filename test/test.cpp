#include <tuple>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "main.hpp"


TEST_CASE("get-bit-true", "get-bit")
{
    auto task = GENERATE(
            std::make_pair(std::vector<unsigned char>{0x80}, 1),
            std::make_pair(std::vector<unsigned char>{0x00, 0x80, 0x80}, 9),
            std::make_pair(std::vector<unsigned char>{0x00, 0x00, 0x80}, 17),
            std::make_pair(std::vector<unsigned char>{0x40}, 2),
            std::make_pair(std::vector<unsigned char>{0x10}, 4),
            std::make_pair(std::vector<unsigned char>{0x04}, 6),
            std::make_pair(std::vector<unsigned char>{0x01}, 8)
    );
    CAPTURE(task.first);
    REQUIRE(get_bit(task.first.cbegin(), task.second) == true);
}

TEST_CASE("get-bit-false", "get-bit")
{
    auto task = GENERATE(
            std::make_pair(std::vector<unsigned char>{0x7F}, 1),
            std::make_pair(std::vector<unsigned char>{0xFF, 0x7F, 0x7F}, 9),
            std::make_pair(std::vector<unsigned char>{0xFF, 0xFF, 0x7F}, 17),
            std::make_pair(std::vector<unsigned char>{0xBF}, 2),
            std::make_pair(std::vector<unsigned char>{0xEF}, 4),
            std::make_pair(std::vector<unsigned char>{0xFB}, 6),
            std::make_pair(std::vector<unsigned char>{0xFE}, 8)
    );
    CAPTURE(task.first);
    REQUIRE(get_bit(task.first.cbegin(), task.second) == false);
}

TEST_CASE("set-bit")
{
    auto task = GENERATE(
            std::make_tuple(std::vector<unsigned char>{0xFF}, 1, std::vector<unsigned char>{0xFF}),
            std::make_tuple(std::vector<unsigned char>{0x0}, 1, std::vector<unsigned char>{0x80}),
            std::make_tuple(std::vector<unsigned char>{0x0}, 2, std::vector<unsigned char>{0x40}),
            std::make_tuple(std::vector<unsigned char>{0x0}, 4, std::vector<unsigned char>{0x10}),
            std::make_tuple(std::vector<unsigned char>{0x0}, 8, std::vector<unsigned char>{0x01}),
            std::make_tuple(std::vector<unsigned char>{0x0, 0x0}, 9, std::vector<unsigned char>{0x00, 0x80}),
            std::make_tuple(std::vector<unsigned char>{0x0, 0x0}, 10, std::vector<unsigned char>{0x00, 0x40})
    );
    CAPTURE(std::get<0>(task), std::get<1>(task));
    set_bit(std::get<0>(task), std::get<1>(task));
    REQUIRE(std::get<0>(task) == std::get<2>(task));
}

TEST_CASE("clear-bit")
{
    auto task = GENERATE(
            std::make_tuple(std::vector<unsigned char>{0x00}, 1, std::vector<unsigned char>{0x0}),
            std::make_tuple(std::vector<unsigned char>{0xFF}, 1, std::vector<unsigned char>{0x7F}),
            std::make_tuple(std::vector<unsigned char>{0xFF}, 2, std::vector<unsigned char>{0xBF}),
            std::make_tuple(std::vector<unsigned char>{0xFF}, 4, std::vector<unsigned char>{0xEF}),
            std::make_tuple(std::vector<unsigned char>{0xFF}, 8, std::vector<unsigned char>{0xFE}),
            std::make_tuple(std::vector<unsigned char>{0xFF, 0xFF}, 9, std::vector<unsigned char>{0xFF, 0x7F}),
            std::make_tuple(std::vector<unsigned char>{0xFF, 0xFF}, 10, std::vector<unsigned char>{0xFF, 0xBF})
    );
    CAPTURE(std::get<0>(task), std::get<1>(task));
    clear_bit(std::get<0>(task), std::get<1>(task));
    REQUIRE(std::get<0>(task) == std::get<2>(task));
}

TEST_CASE("initial_permute")
{
	auto task = GENERATE(
		std::make_pair(std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					   std::vector<unsigned char>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		std::make_pair(std::vector<unsigned char>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
					   std::vector<unsigned char>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
		std::make_pair(std::vector<unsigned char>{0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40},
					   std::vector<unsigned char>{0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		std::make_pair(std::vector<unsigned char>{0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50},
					   std::vector<unsigned char>{0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	);
	CAPTURE(task.first);
	std::vector<unsigned char> target(8);
	permute(target, task.first, initial_permute_table);
	REQUIRE(target == task.second);
}

TEST_CASE("schedule_key_rotl")
{
	auto task = GENERATE(
		std::make_pair(std::array<unsigned char, 7>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
					   std::array<unsigned char, 7>{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
		std::make_pair(std::array<unsigned char, 7>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
					   std::array<unsigned char, 7>{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}),
		std::make_pair(std::array<unsigned char, 7>{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
					   std::array<unsigned char, 7>{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55}),
		std::make_pair(std::array<unsigned char, 7>{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
					   std::array<unsigned char, 7>{0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA})
	);
	CAPTURE(task.first);
	schedule_key_rotl(task.first);
	REQUIRE(task.first == task.second);
}