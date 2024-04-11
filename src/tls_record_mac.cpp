#include <algorithm>
#include <iterator>
#include <stdexcept>

#include "hmac.hpp"

#include "tls_record_mac.hpp"

TlsRecordMac::TlsRecordMac(const std::vector<unsigned char> &secret) : secret(secret)
{

}

void TlsRecordMac::append_mac(TlsRecord &record)
{
    std::vector<unsigned char> buffer{};
    for (int i = 0; i < 8; ++i)
    {
        buffer.push_back(sequence_number >> (8 * (7 - i)) & 0xFF);
    }
    record.write_to(std::back_inserter(buffer));
    const auto mac = hmac_sha1(buffer, secret);
    std::copy(mac.begin(), mac.end(), std::back_inserter(record.payload));
    ++sequence_number;
}

void TlsRecordMac::verify_and_clear_mac(TlsRecord &record)
{
    if (record.payload.size() < 20)
    {
        throw std::runtime_error("tls error: bad record mac length");
    }
    std::array<unsigned char, 20> mac{};
    std::copy(record.payload.end() - 20, record.payload.end(), mac.begin());

    std::vector<unsigned char> buffer{};
    for (int i = 0; i < 8; ++i)
    {
        buffer.push_back(sequence_number >> (8 * (7 - i)) & 0xFF);
    }
    buffer.push_back(static_cast<char>(record.content_type));
    buffer.push_back(record.protocol_version.major);
    buffer.push_back(record.protocol_version.minor);
    buffer.push_back(static_cast<char>(((record.payload.size() - 20) >> 8) & 0xFF));
    buffer.push_back(static_cast<char>(((record.payload.size() - 20) >> 0) & 0xFF));
    std::copy(record.payload.begin(), record.payload.end() - 20, std::back_inserter(buffer));
    if (hmac_sha1(buffer, secret) != mac)
    {
        throw std::runtime_error("tls error: bad record mac signature");
    }
    record.payload.resize(record.payload.size() - 20);
    ++sequence_number;
}

std::vector<char> TlsRecord::serialise() const
{
    std::vector<char> result{};
    result.push_back(static_cast<char>(content_type));
    result.push_back(protocol_version.major);
    result.push_back(protocol_version.minor);
    result.push_back(static_cast<char>((payload.size() >> 8) & 0xFF));
    result.push_back(static_cast<char>((payload.size() >> 0) & 0xFF));
    std::copy(payload.begin(), payload.end(), std::back_inserter(result));
    return result;
}

void TlsRecord::write_to(auto begin) const
{
    *begin++ = static_cast<char>(content_type);
    *begin++ = protocol_version.major;
    *begin++ = protocol_version.minor;
    *begin++ = static_cast<char>((payload.size() >> 8) & 0xFF);
    *begin++ = static_cast<char>((payload.size() >> 0) & 0xFF);
    std::copy(payload.begin(), payload.end(), begin);
}
