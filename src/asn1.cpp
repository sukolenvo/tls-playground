#include <algorithm>
#include <array>
#include <stdexcept>

#include "asn1.hpp"


Asn1Tag getTag(auto type)
{
	switch (type & 0xC0)
	{
	case 0:
		return Asn1Tag::Universal;
	case 0x80:
		return Asn1Tag::ContextSpecific;
	default:
		throw std::runtime_error("unexpected ASN.1 type tag");
	}
}

Asn1Type getType(auto type)
{
	static const std::array asn1type_values{ 0, 1, 2, 3, 4, 5, 6, 7, 10, 12, 16, 17, 18, 19, 22, 23, 24 };
	for (const auto asn1type_value: asn1type_values)
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
	if (*begin & 0x80)
	{
		const auto bytes = *begin & 0x7F;
		if (bytes == 0 || bytes > 8)
		{
			throw std::runtime_error("unsupported length");
		}
		std::uint_fast64_t result{};
		for (auto i = 0; i < bytes; ++i)
		{
			if (++begin == end)
			{
				throw std::runtime_error("malformed input: length is not provided");
			}
			result <<= 8;
			result |= *begin;
		}
		++begin;
		return result;
	}
	else
	{
		return *begin++;
	}
}

std::vector<Asn1> parse_asn1(auto &begin, const auto end)
{
	std::vector<Asn1> result{};
	while (begin != end)
	{
		const auto typeValue = *begin++;
		Asn1 value{};
		value.tag = getTag(typeValue);
		value.constructed = (typeValue & 0x20) != 0;
		value.type = getType(typeValue);
		const auto length = parse_length(begin, end);
		if (value.constructed)
		{
			value.data = parse_asn1(begin, begin + length);
		}
		else if (value.type == Asn1Type::Integer || value.type == Asn1Type::OID || value.type == Asn1Type::UtcTime ||
				 value.type == Asn1Type::GeneralizedTime || value.type == Asn1Type::OctetString)
		{
			std::vector<unsigned char> number{};
			std::copy_n(begin, length, std::back_inserter(number));
			value.data = BigNumber(number);
			begin += length;
		}
		else if (value.type == Asn1Type::Null)
		{
			if (length != 0)
			{
				throw std::runtime_error("expecting null type to be of length 0");
			}
			value.data = ZERO;
		}
		else if (value.type == Asn1Type::PrintableString || value.type == Asn1Type::Ia5String ||
				 value.type == Asn1Type::Utf8String)
		{
			std::string str{};
			str.resize(length);
			std::copy_n(begin, length, str.data());
			value.data = str;
			begin += length;
		}
		else if (value.type == Asn1Type::BitString)
		{
			if (*begin++ != 0)
			{
				throw std::runtime_error("big string with non-zero padding");
			}
			std::vector<unsigned char> number{};
			std::copy_n(begin, length, std::back_inserter(number));
			value.data = BigNumber(number);
			begin += length - 1;
		}
		else if (value.type == Asn1Type::Boolean)
		{
			value.data = *begin++ == 0xFF;
		} else
		{
			throw std::runtime_error("unexpected type");
		}
		result.push_back(value);
	}
	return result;
}

std::vector<Asn1> parse_asn1(const std::vector<unsigned char> &certificate)
{
	auto begin = certificate.begin();
	return parse_asn1(begin, certificate.end());
}