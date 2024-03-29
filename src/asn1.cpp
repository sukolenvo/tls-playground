#include <array>
#include <cstdint>
#include <stdexcept>

#include "asn1.hpp"


Asn1Tag getTag(auto type)
{
	switch (type & 0xC0)
	{
	case 0:
		return Asn1Tag::Universal;
	case 0x4:
		return Asn1Tag::ContextSpecific;
	default:
		throw std::runtime_error("unexpected ASN.1 type tag");
	}
}

Asn1Type getType(auto type)
{
	static const std::array asn1type_values{ 1, 2, 3, 4, 5, 6, 7, 10, 12, 16, 17, 18, 19, 22, 23, 24 };
	for (const auto asn1type_value : asn1type_values)
	{
		if ((type & 0x1F) == asn1type_value)
		{
			return static_cast<Asn1Type>(asn1type_value);
		}
	}
	throw std::runtime_error("unexpected ASN.1 type");
}

std::uint_fast64_t parse_length(auto &begin, const auto end)
{
	if (begin == end)
	{
		throw std::runtime_error("malformed input: length expected got EOF");
	}
	if (*begin & 0x80) {
		const auto bytes = *begin & 0x7F;
		if (bytes == 0 || bytes > 8)
		{
			throw std::runtime_error("unsupported length");
		}
		std::uint_fast64_t result{};
		for (auto i = 0; i < bytes; ++i)
		{
			if (++begin == end) {
				throw std::runtime_error("malformed input: length is not provided");
			}
			result <<= 8;
			result |= *begin;
		}
		++begin;
		return result;
	} else {
		return *begin++;
	}
}

std::vector<Asn1> parse(auto begin, const auto end)
{
	while (begin != end)
	{
		const auto typeValue = *begin++;
		const auto tag = getTag(typeValue);
		const auto constructed = (typeValue & 0x20) != 0;
		const auto type = getType(typeValue);
		const auto length = parse_length(begin, end);
	}
	return Asn1();
}
