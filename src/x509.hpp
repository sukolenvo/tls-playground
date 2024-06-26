#ifndef TLS_PLAYGROUND_X509_HPP
#define TLS_PLAYGROUND_X509_HPP

#include <chrono>
#include <string>
#include <vector>

#include "math.hpp"

enum class AlgorithmType
{
    RsaSha1,
    RsaSha256,
    RsaMd5,
    Rsa
};

struct AlgorithmInfo
{
    AlgorithmType type;
    std::vector<unsigned char> params;
};

struct PublicKeyInfo
{
    AlgorithmInfo algorithm;
    std::vector<unsigned char> key;
};

struct Name
{
    std::string country;
    std::string state_or_province;
    std::string locality_name;
    std::string organization_name;
    std::string organisation_unit_name;
    std::string common_name;

    int operator<=>(const Name &other) const = default;
};

enum class KeyUsageType : unsigned char
{
    DigitalSignature = 0,
    NonRepudiation = 1,
    KeyEncipherment = 2,
    DataEncipherment = 3,
    KeyAgreement = 4,
    KeyCertSign = 5,
    CrlSign = 6,
    EncipherOnly = 7,
    DecipherOnly = 8
};

struct Extensions
{
    std::vector<KeyUsageType> key_usage;
    bool is_ca;
};

struct x509Certificate
{
    int version;
    BigNumber serial_number;
    AlgorithmInfo signature_algorithm;
    Name issuer;
    std::chrono::time_point<std::chrono::system_clock> not_before;
    std::chrono::time_point<std::chrono::system_clock> not_after;
    Name subject;
    PublicKeyInfo subject_public_key;
    Extensions extensions;
};

struct SignedX509Certificate
{
    x509Certificate tbs_certificate;
    AlgorithmInfo signature_algorithm;
    BigNumber signature;
};

SignedX509Certificate parse_certificate(const std::vector<unsigned char> &certificate);

#endif //TLS_PLAYGROUND_X509_HPP
