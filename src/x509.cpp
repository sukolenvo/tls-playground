#include <stdexcept>

#include "asn1.hpp"
#include "x509.hpp"

AlgorithmType parse_algorithm_type(const Asn1 &asn1)
{
	if (asn1.type != Asn1Type::OID)
	{
		throw std::runtime_error("malformed algorithm: type is not OID");
	}
	const auto algorithm_oid = std::get<BigNumber>(asn1.data);
	// list of algorithm OIDs: https://oidref.com/1.2.840.113549.1.1.11
	if (algorithm_oid == BigNumber({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x1, 0x1, 0x1 }))
	{
		return AlgorithmType::Rsa;
	}
	if (algorithm_oid == BigNumber({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x1, 0x1, 0x4 }))
	{
		return AlgorithmType::RsaMd5;
	}
	if (algorithm_oid == BigNumber({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x1, 0x1, 0x5 }))
	{
		return AlgorithmType::RsaSha1;
	}
	if (algorithm_oid == BigNumber({ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x1, 0x1, 0xb }))
	{
		return AlgorithmType::RsaSha256;
	}
	throw std::runtime_error("unknown algorithm");
}

AlgorithmInfo parse_algorithm(const Asn1 &asn)
{
	const auto algorithm_asn = std::get<std::vector<Asn1>>(asn.data);
	if (algorithm_asn.size() != 2)
	{
		throw std::runtime_error("malformed algorithm");
	}
	return {
			parse_algorithm_type(algorithm_asn[0]),
			std::get<BigNumber>(algorithm_asn[1].data).data()
	};
}

std::chrono::time_point<std::chrono::system_clock> parse_asn1_time(const Asn1 &asn)
{
	if (asn.type != Asn1Type::UtcTime && asn.type != Asn1Type::GeneralizedTime)
	{
		throw std::runtime_error("invalid time type");
	}
	const auto time = std::get<BigNumber>(asn.data);
	std::chrono::year year{};
	size_t monthIdx{};
	if (asn.type == Asn1Type::UtcTime)
	{
		year = std::chrono::year{ 1900 + (time.data().at(0) - '0') * 10 + (time.data().at(1) - '0') };
		if (year < std::chrono::year{ 1950 })
		{
			year += std::chrono::years{ 100 };
		}
		monthIdx = 2;
	}
	else
	{
		year = std::chrono::year{ (time.data().at(0) - '0') * 1000
								  + (time.data().at(1) - '0') * 100
								  + (time.data().at(2) - '0') * 10
								  + (time.data().at(3) - '0') };
		monthIdx = 4;
	}
	if (time.data().size() != monthIdx + 11)
	{
		throw std::runtime_error("malformed time: unexpected length");
	}
	const std::chrono::month month{
			static_cast<unsigned int>((time.data()[monthIdx] - '0') * 10 + (time.data()[monthIdx + 1] - '0')) };
	const std::chrono::day day_of_month{
			static_cast<unsigned int>((time.data()[monthIdx + 2] - '0') * 10 + (time.data()[monthIdx + 3] - '0')) };
	const std::chrono::hours hours{ (time.data()[monthIdx + 4] - '0') * 10 + (time.data()[monthIdx + 5] - '0') };
	const std::chrono::minutes minutes{ (time.data()[monthIdx + 6] - '0') * 10 + (time.data()[monthIdx + 7] - '0') };
	const std::chrono::minutes seconds{ (time.data()[monthIdx + 8] - '0') * 10 + (time.data()[monthIdx + 9] - '0') };
	const auto time_of_day = hours + minutes + seconds;
	if (time.data()[monthIdx + 10] != 'Z')
	{
		throw std::runtime_error("malformed UTC time: 'Z' suffix expected");
	}

	return std::chrono::sys_days{ std::chrono::year_month_day{ year, month, day_of_month }} + time_of_day;
}

Name parse_asn1_name(const Asn1 &asn)
{
	const auto name_asn = std::get<std::vector<Asn1>>(asn.data);
	Name name{};
	for (const auto &distinguished_name: name_asn)
	{
		if (distinguished_name.type != Asn1Type::Set)
		{
			throw std::runtime_error("malformed distinguished name");
		}
		const auto name_items = std::get<std::vector<Asn1>>(distinguished_name.data);
		for (const auto &name_item: name_items)
		{
			const auto key_and_value = std::get<std::vector<Asn1>>(name_item.data);
			if (key_and_value.size() != 2 || key_and_value[0].type != Asn1Type::OID)
			{
				throw std::runtime_error("malformed distinguished name values");
			}
			const auto name_oid = std::get<BigNumber>(key_and_value[0].data);
			// oids list: https://oidref.com/2.5.4.49
			if (name_oid == BigNumber({ 0x55, 0x4, 0x6 }))
			{
				name.country = std::get<std::string>(key_and_value[1].data);
			}
			else if (name_oid == BigNumber({ 0x55, 0x4, 0x8 }))
			{
				name.state_or_province = std::get<std::string>(key_and_value[1].data);
			}
			else if (name_oid == BigNumber({ 0x55, 0x4, 0xa }))
			{
				name.organization_name = std::get<std::string>(key_and_value[1].data);
			}
			else if (name_oid == BigNumber({ 0x55, 0x4, 0xb }))
			{
				name.organisation_unit_name = std::get<std::string>(key_and_value[1].data);
			}
			else if (name_oid == BigNumber({ 0x55, 0x4, 0x3 }))
			{
				name.common_name = std::get<std::string>(key_and_value[1].data);
			}
		}
	}
	return name;
}

PublicKeyInfo parse_public_key(const Asn1 &asn)
{
	const auto key_asn = std::get<std::vector<Asn1>>(asn.data);
	if (key_asn.size() != 2)
	{
		throw std::runtime_error("malform public key");
	}
	return {
			parse_algorithm(key_asn[0]),
			std::get<BigNumber>(key_asn[1].data).data()
	};
}

x509Certificate parse_tbs_certificate(const Asn1 &asn)
{
	if (!std::holds_alternative<std::vector<Asn1>>(asn.data))
	{
		throw std::runtime_error("malformed tbs certificate");
	}
	const auto tbs_certificate_asn = std::get<std::vector<Asn1>>(asn.data);
	if (tbs_certificate_asn.empty())
	{
		throw std::runtime_error("empty tbs certificate");
	}
	auto version = 0;
	auto versionIdx = -1;
	if (tbs_certificate_asn.at(0).tag == Asn1Tag::ContextSpecific)
	{
		const auto version_asn = std::get<std::vector<Asn1>>(tbs_certificate_asn.at(0).data);
		if (version_asn.size() != 1)
		{
			throw std::runtime_error("malformed version explicit tag");
		}
		version = std::get<BigNumber>(version_asn[0].data).data().at(0);
		if (version > 2)
		{
			throw std::runtime_error("unsupported certificate version");
		}
		versionIdx = 0;
	}
	const auto serialNumber = std::get<BigNumber>(tbs_certificate_asn.at(versionIdx + 1).data);
	const auto algorithm = parse_algorithm(tbs_certificate_asn.at(versionIdx + 2));
	const auto issuer = parse_asn1_name(tbs_certificate_asn.at(versionIdx + 3));
	const auto notBefore = parse_asn1_time(
			std::get<std::vector<Asn1>>(tbs_certificate_asn.at(versionIdx + 4).data).at(0));
	const auto notAfter = parse_asn1_time(
			std::get<std::vector<Asn1>>(tbs_certificate_asn.at(versionIdx + 4).data).at(1));
	const auto subject = parse_asn1_name(tbs_certificate_asn.at(versionIdx + 5));
	const auto subject_public_key = parse_public_key(tbs_certificate_asn.at(versionIdx + 6));

	return {
			version,
			serialNumber,
			algorithm,
			issuer,
			notBefore,
			notAfter,
			subject,
			subject_public_key
	};
}

SignedX509Certificate parse_signed_certificate(const Asn1 &asn)
{
	const auto certificate_asn = std::get<std::vector<Asn1>>(asn.data);
	if (!asn.constructed || certificate_asn.size() != 3)
	{
		throw std::runtime_error("malformed signed certificate structure");
	}
	const auto signature_algorithm = parse_algorithm(certificate_asn.at(1));
	if (!std::holds_alternative<BigNumber>(certificate_asn.at(2).data))
	{
		throw std::runtime_error("signature is not a BigNumber");
	}
	const auto signature = std::get<BigNumber>(certificate_asn.at(2).data);
	const auto tbs_certificate = parse_tbs_certificate(certificate_asn.at(0));
	return { tbs_certificate, signature_algorithm, signature };
}

SignedX509Certificate parse_certificate(const std::vector<unsigned char> &certificate)
{
	const auto asn = parse_asn1(certificate);
	if (asn.size() != 1)
	{
		throw std::runtime_error("Invalid ASN.1 structure");
	}
	return parse_signed_certificate(asn.front());
}
