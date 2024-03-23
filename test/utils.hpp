#ifndef TLS_PLAYGROUND_UTILS_HPP
#define TLS_PLAYGROUND_UTILS_HPP

#include <iomanip>
#include <sstream>
#include <string>

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

#endif //TLS_PLAYGROUND_UTILS_HPP
