#ifndef TLS_PLAYGROUND_ASN1_HPP
#define TLS_PLAYGROUND_ASN1_HPP

#include <string>
#include <variant>
#include <vector>

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
	bool constructed;
	Asn1Type type;
	std::variant<int, std::string, std::vector<Asn1>> data;
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
Asn1 parse(const std::vector<unsigned char> &data);

#endif //TLS_PLAYGROUND_ASN1_HPP
