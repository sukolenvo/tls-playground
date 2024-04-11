#ifndef TLS_PLAYGROUND_TLS_RECORD_MAC_HPP
#define TLS_PLAYGROUND_TLS_RECORD_MAC_HPP

#include <cstdint>
#include <vector>

struct ProtocolVersion
{
    char major, minor;

    int operator<=>(const ProtocolVersion &other) const = default;
};

inline const ProtocolVersion tls1_0_version = { 3, 1 };

enum class TlsRecordType : char
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23
};

struct TlsRecord
{
    TlsRecordType content_type;
    ProtocolVersion protocol_version;
    std::vector<unsigned char> payload;

    [[nodiscard]]
    std::vector<char> serialise() const;

    void write_to(auto begin) const;
};

class TlsRecordMac
{
    uint64_t sequence_number{};
    std::vector<unsigned char> secret;
public:
    explicit TlsRecordMac(const std::vector<unsigned char> &secret);

    void append_mac(TlsRecord &record);

    void verify_and_clear_mac(TlsRecord &record);
};

#endif //TLS_PLAYGROUND_TLS_RECORD_MAC_HPP
