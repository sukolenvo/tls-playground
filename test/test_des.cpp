#include <tuple>
#include <vector>

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "des.hpp"


TEST_CASE("set-bit")
{
	auto task = GENERATE(
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF }, 1, std::array<unsigned char, 2>{ 0xFF }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0 }, 1, std::array<unsigned char, 2>{ 0x80 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0 }, 2, std::array<unsigned char, 2>{ 0x40 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0 }, 4, std::array<unsigned char, 2>{ 0x10 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0 }, 8, std::array<unsigned char, 2>{ 0x01 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0, 0x0 }, 9, std::array<unsigned char, 2>{ 0x00, 0x80 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0x0, 0x0 }, 10, std::array<unsigned char, 2>{ 0x00, 0x40 })
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	set_bit(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task) == std::get<2>(task));
}

TEST_CASE("clear-bit")
{
	auto task = GENERATE(
			std::make_tuple(std::array<unsigned char, 2>{ 0x00 }, 1, std::array<unsigned char, 2>{ 0x0 }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF }, 1, std::array<unsigned char, 2>{ 0x7F }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF }, 2, std::array<unsigned char, 2>{ 0xBF }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF }, 4, std::array<unsigned char, 2>{ 0xEF }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF }, 8, std::array<unsigned char, 2>{ 0xFE }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF, 0xFF }, 9, std::array<unsigned char, 2>{ 0xFF, 0x7F }),
			std::make_tuple(std::array<unsigned char, 2>{ 0xFF, 0xFF }, 10, std::array<unsigned char, 2>{ 0xFF, 0xBF })
	);
	CAPTURE(std::get<0>(task), std::get<1>(task));
	clear_bit(std::get<0>(task), std::get<1>(task));
	REQUIRE(std::get<0>(task) == std::get<2>(task));
}

TEST_CASE("initial_permute")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					std::array<unsigned char, 8>{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
			std::make_pair(std::vector<unsigned char>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
					std::array<unsigned char, 8>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),
			std::make_pair(std::vector<unsigned char>{ 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 },
					std::array<unsigned char, 8>{ 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
			std::make_pair(std::vector<unsigned char>{ 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50, 0x50 },
					std::array<unsigned char, 8>{ 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 })
	);
	CAPTURE(task.first);
	std::array<unsigned char, 8> target;
	const std::array<unsigned int, 64> table = std::array<unsigned int, 64>{
			58, 50, 42, 34, 26, 18, 10, 2,
			60, 52, 44, 36, 28, 20, 12, 4,
			62, 54, 46, 38, 30, 22, 14, 6,
			64, 56, 48, 40, 32, 24, 16, 8,
			57, 49, 41, 33, 25, 17, 9, 1,
			59, 51, 43, 35, 27, 19, 11, 3,
			61, 53, 45, 37, 29, 21, 13, 5,
			63, 55, 47, 39, 31, 23, 15, 7
	};
	permute(target, task.first, table);
	REQUIRE(target == task.second);
}

TEST_CASE("schedule_key_rotl")
{
	auto task = GENERATE(
			std::make_pair(std::array<unsigned char, 7>{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
					std::array<unsigned char, 7>{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }),
			std::make_pair(std::array<unsigned char, 7>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
					std::array<unsigned char, 7>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }),
			std::make_pair(std::array<unsigned char, 7>{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA },
					std::array<unsigned char, 7>{ 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 }),
			std::make_pair(std::array<unsigned char, 7>{ 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 },
					std::array<unsigned char, 7>{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA })
	);
	CAPTURE(task.first);
	schedule_key_rotl(task.first);
	REQUIRE(task.first == task.second);
}

TEST_CASE("schedule_key_rotr")
{
	auto task = GENERATE(
			std::array<unsigned char, 7>{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
			std::array<unsigned char, 7>{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
			std::array<unsigned char, 7>{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA },
			std::array<unsigned char, 7>{ 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 },
			std::array<unsigned char, 7>{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd }
	);
	CAPTURE(task);
	auto copy = task;
	schedule_key_rotl(copy);
	schedule_key_rotr(copy);
	REQUIRE(copy == task);
}

TEST_CASE("des_ecb_pkcs5")
{
	auto task = GENERATE(
			std::vector<unsigned char>{ 'a', 'b', 'c' },
			std::vector<unsigned char>{ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' },
			std::vector<unsigned char>{ '1', '2', '3', '4', '5', '6', '7', '8', '9' }
	);
	CAPTURE(task);
	const auto key = std::array<unsigned char, 8>{ 1, 2, 3, 4, 5, 6, 7, 8 };
	const std::vector<unsigned char> encrypted = des_ecb_pkcs5_encrypt(task, key);
	const std::vector<unsigned char> decrypted = des_ecb_pkcs5_decrypt(encrypted, key);
	REQUIRE(decrypted == task);
}

TEST_CASE("des_cbc_pkcs5")
{
	auto task = GENERATE(
			std::vector<unsigned char>{ 'a', 'b', 'c' },
			std::vector<unsigned char>{ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' },
			std::vector<unsigned char>{ '1', '2', '3', '4', '5', '6', '7', '8', '9' }
	);
	CAPTURE(task);
	const auto key = std::array<unsigned char, 8>{ 1, 2, 3, 4, 5, 6, 7, 8 };
	const auto iv = std::array<unsigned char, 8>{ 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1a, 0x1b };
	const std::vector<unsigned char> encrypted = des_cbc_pkcs5_encrypt(task, key, iv);
	const std::vector<unsigned char> decrypted = des_cbc_pkcs5_decrypt(encrypted, key, iv);
	REQUIRE(decrypted == task);
}