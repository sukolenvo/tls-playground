#include <tuple>

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