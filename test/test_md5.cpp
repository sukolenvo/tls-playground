#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <iomanip>
#include <sstream>
#include <string>
#include <utility>

#include "md5.hpp"

template<class InputIt>
std::string hexStr(InputIt first, InputIt last)
{
	std::stringstream ss;
	ss << std::hex;

	while(first != last)
	{
		ss << std::setw(2) << std::setfill('0') << (int)*first++;
	}

	return ss.str();
}

TEST_CASE("md5_hash")
{
	auto task = GENERATE(
			std::make_pair(std::vector<unsigned char>{ 'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!' },
					"ed076287532e86365e841e92bfc50d8c")
	);

	CAPTURE(task.first);
	const auto result = md5_hash(task.first);
	REQUIRE(hexStr(result.begin(), result.end()) == task.second);
}