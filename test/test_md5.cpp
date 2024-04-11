#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <utility>

#include "utils.hpp"
#include "md5.hpp"

TEST_CASE("md5_hash")
{
    auto task = GENERATE(
            std::make_pair(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
                    "ed076287532e86365e841e92bfc50d8c"),
            std::make_pair(std::vector<unsigned char>{}, "d41d8cd98f00b204e9800998ecf8427e"),
            std::make_pair(std::vector<unsigned char>(100, 'a'),
                    "36a92cc94a9e0fa21f625f8bfb007adf"),
            std::make_pair(std::vector<unsigned char>{
                    0x01, 0x00, 0x00, 0x29, 0x03, 0x01, 0x66, 0x13, 0x20, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00, 0x02, 0x00, 0x00,
                    0x46, 0x03, 0x01, 0x66, 0x12, 0x90, 0x5c, 0x38, 0x30, 0x37, 0xae, 0x38, 0x92, 0x18, 0x4f, 0xd4
            }, "b1960acd11591490bf1e28272cbf0321")
    );

    CAPTURE(task.first);
    const auto result = md5_hash(task.first);
    REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}