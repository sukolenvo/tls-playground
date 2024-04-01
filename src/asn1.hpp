#ifndef TLS_PLAYGROUND_ASN1_HPP
#define TLS_PLAYGROUND_ASN1_HPP

#include <string>
#include <variant>
#include <vector>

#include "math.hpp"

enum class Asn1Tag
{
	Universal,
	/**
	 * aka explicit.
	 */
	ContextSpecific
};

enum class Asn1Type : unsigned char
{
	Ber = 0,
	Boolean = 1,
	Integer = 2,
	BitString = 3,
	OctetString = 4,
	Null = 5,
	OID = 6,
	ObjectDescriptor = 7,
	Enumerated = 10,
	Utf8String = 12,
	Sequence = 16,
	Set = 17,
	NumericString = 18,
	PrintableString = 19,
	Ia5String = 22,
	UtcTime = 23,
	GeneralizedTime = 24,
};

struct Asn1
{
	Asn1Tag tag;
	unsigned char explicit_tag_value;
	bool constructed;
	Asn1Type type;
	std::variant<bool, std::vector<Asn1>, BigNumber, std::string> data;
};

struct Asn1Value : Asn1
{
	std::vector<unsigned char> data;
};

struct Asn1Sequence : Asn1
{
	std::vector<Asn1> members;
};

[[nodiscard]]
std::vector<Asn1> parse_asn1(const std::vector<unsigned char> &certificate);

#endif //TLS_PLAYGROUND_ASN1_HPP
