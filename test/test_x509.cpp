#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include "asn1.hpp"
#include "utils.hpp"
#include "x509.hpp"

TEST_CASE("parse x509 certificate")
{
    const auto file_data = read_file("resources/cert.der");
    const std::vector<unsigned char> data{ file_data.begin(), file_data.end() };
    const auto result = parse_certificate(data);
    REQUIRE(result.tbs_certificate.version == 2);
    REQUIRE(result.signature_algorithm.type == AlgorithmType::RsaSha256);
    REQUIRE(result.signature.data().empty() == false);
    REQUIRE(result.tbs_certificate.serial_number.data().empty() == false);
    REQUIRE(result.tbs_certificate.signature_algorithm.type == result.signature_algorithm.type);
    REQUIRE(result.tbs_certificate.issuer.country == "AU");
    REQUIRE(result.tbs_certificate.issuer.state_or_province == "Some-State");
    REQUIRE(result.tbs_certificate.issuer.locality_name.empty());
    REQUIRE(result.tbs_certificate.issuer.organization_name == "SW");
    REQUIRE(result.tbs_certificate.issuer.organisation_unit_name == "SW.Unit");
    REQUIRE(result.tbs_certificate.issuer.common_name == "sw.ninja");
    REQUIRE(result.tbs_certificate.subject == result.tbs_certificate.issuer);
    REQUIRE(result.tbs_certificate.subject_public_key.algorithm.type == AlgorithmType::Rsa);
    REQUIRE(result.tbs_certificate.subject_public_key.key.empty() == false);
    using namespace std::chrono;
    using namespace std::literals;
    REQUIRE(result.tbs_certificate.not_before == sys_days{ 28d / std::chrono::March / 2024 } + 19h + 16min + 26s);
    REQUIRE(result.tbs_certificate.not_after == sys_days{ 27d / std::chrono::April / 2024 } + 19h + 16min + 26s);
    REQUIRE(result.tbs_certificate.extensions.is_ca);
    REQUIRE(result.tbs_certificate.extensions.key_usage.empty());
}

TEST_CASE("parse subject public key info")
{
    const auto file_data = read_file("resources/google.der");
    const std::vector<unsigned char> data{ file_data.begin(), file_data.end() };
    const auto result = parse_certificate(data);
    REQUIRE(result.tbs_certificate.subject_public_key.algorithm.type == AlgorithmType::Rsa);
    const auto key_asn = parse_asn1(result.tbs_certificate.subject_public_key.key);
    REQUIRE(key_asn.constructed);
    const auto mod_exp = std::get<std::vector<Asn1>>(key_asn.data);
    REQUIRE(mod_exp.size() == 2);
    REQUIRE(std::holds_alternative<BigNumber>(mod_exp[0].data));
    REQUIRE(std::holds_alternative<BigNumber>(mod_exp[1].data));
}
