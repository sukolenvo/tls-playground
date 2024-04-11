#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <variant>

#include "aes.hpp"
#include "asn1.hpp"
#include "rsa.hpp"
#include "sha.hpp"
#include "tls_prf.hpp"
#include "tls_tcp_socket.hpp"
#include "x509.hpp"

enum class CipherSuiteType : unsigned int
{
    TLS_NULL_WITH_NULL_NULL = 0x0,
    TLS_RSA_WITH_NULL_MD5 = 0x1,
    TLS_RSA_WITH_NULL_SHA = 0x2,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5 = 0x3,
    TLS_RSA_WITH_RC4_128_MD5 = 0x4,
    TLS_RSA_WITH_RC4_128_SHA = 0x5,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 = 0x6,
    TLS_RSA_WITH_IDEA_CBC_SHA = 0x7,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA = 0x8,
    TLS_RSA_WITH_DES_CBC_SHA = 0x9,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0xa,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x2f,
};

enum class CompressionType : char
{
    NONE = 0
};

enum class HandshakeMessageType : char
{
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20
};

struct HandshakeMessage
{
    HandshakeMessageType type;
    std::vector<unsigned char> payload;

    [[nodiscard]]
    std::vector<unsigned char> serialise() const
    {
        std::vector<unsigned char> result{};
        result.push_back(static_cast<unsigned char>(type));
        result.push_back(static_cast<unsigned char>((payload.size() >> 16) & 0xFF));
        result.push_back(static_cast<unsigned char>((payload.size() >> 8) & 0xFF));
        result.push_back(static_cast<unsigned char>((payload.size() >> 0) & 0xFF));
        std::copy(payload.begin(), payload.end(), std::back_inserter(result));
        return result;
    }
};

struct HandshakeClientHelloPayload
{
    ProtocolVersion protocol_version;
    std::array<unsigned char, 32> random_bytes;
    std::string session_id;
    std::vector<CipherSuiteType> cipher_suites;
    std::vector<CompressionType> compression_methods;

    HandshakeClientHelloPayload() : protocol_version(tls1_0_version),
                                    random_bytes(new_random()),
                                    cipher_suites({ CipherSuiteType::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
                                                    CipherSuiteType::TLS_RSA_WITH_DES_CBC_SHA,
                                                    CipherSuiteType::TLS_RSA_WITH_AES_128_CBC_SHA }),
                                    compression_methods({ CompressionType::NONE })
    {

    }

    static std::array<unsigned char, 32> new_random()
    {
        const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch());
        std::array<unsigned char, 32> random{};
        random[0] = static_cast<char>((seconds.count() >> 24) & 0xFF);
        random[1] = static_cast<char>((seconds.count() >> 16) & 0xFF);
        random[2] = static_cast<char>((seconds.count() >> 8) & 0xFF);
        random[3] = static_cast<char>((seconds.count() >> 0) & 0xFF);
        return random;
    }

    [[nodiscard]]
    HandshakeMessage to_handshake_message() const
    {
        std::vector<unsigned char> payload{};
        payload.push_back(protocol_version.major);
        payload.push_back(protocol_version.minor);
        std::copy(random_bytes.begin(), random_bytes.end(), std::back_inserter(payload));
        payload.push_back(session_id.size());
        std::copy(session_id.begin(), session_id.end(), std::back_inserter(payload));
        const auto cipher_field_length = cipher_suites.size() * 2;
        payload.push_back((cipher_field_length >> 8) & 0xFF);
        payload.push_back((cipher_field_length) & 0xFF);
        for (const auto cipher_suite: cipher_suites)
        {
            payload.push_back((static_cast<unsigned int>(cipher_suite) >> 8) & 0xFF);
            payload.push_back((static_cast<unsigned int>(cipher_suite) >> 0) & 0xFF);
        }
        payload.push_back(compression_methods.size());
        for (const auto compression: compression_methods)
        {
            payload.push_back(static_cast<unsigned char>(compression));
        }
        return {
                HandshakeMessageType::ClientHello,
                payload
        };
    }
};

struct ServerHello
{
    ProtocolVersion protocol_version;
    std::array<unsigned char, 32> random;
    std::string session;
    CipherSuiteType cipher_suite_type;
    CompressionType compression_type;
};

ServerHello parse_server_hello(auto begin, const auto end)
{
    const char major = *begin++;
    const char minor = *begin++;
    std::array<unsigned char, 32> random{};
    std::copy_n(begin, 32, random.begin());
    begin += 32;
    const auto session_length = *begin++;
    const auto session = std::string(begin, begin + session_length);
    begin += session_length;
    const auto cipher = *begin++ << 8 | *begin++;
    const auto compression = *begin++;
    if (begin != end)
    {
        throw std::runtime_error("malformed server_hello");
    }
    return {
            { major, minor },
            random,
            session,
            static_cast<CipherSuiteType>(cipher),
            static_cast<CompressionType>(compression)
    };
}

std::vector<SignedX509Certificate> parse_x509_certificate_chain(auto begin, const auto end)
{
//	const auto length = (*(begin + 0) & 0xFF) << 16
//						| ((*(begin + 1) & 0xFF) << 8)
//						| ((*(begin + 2) & 0xFF) << 0);
    begin += 3;
    std::vector<SignedX509Certificate> chain{};
    while (begin < end)
    {
        const auto certificate_length = (*(begin + 0) & 0xFF) << 16
                                        | ((*(begin + 1) & 0xFF) << 8)
                                        | ((*(begin + 2) & 0xFF) << 0);
        begin += 3;
        std::vector<unsigned char> certificate(certificate_length);
        std::copy_n(begin, certificate_length, certificate.begin());
        begin += certificate_length;
        chain.push_back(parse_certificate(certificate));
    }
    return chain;
}

struct HandshakeClientKeyExchangePayload
{
    std::vector<unsigned char> encrypted_premaster_secret;

    HandshakeMessage to_handshake_message()
    {
        std::vector<unsigned char> payload(encrypted_premaster_secret.size() + 2);
        payload[0] = (encrypted_premaster_secret.size() >> 8) & 0xFF;
        payload[1] = (encrypted_premaster_secret.size() >> 0) & 0xFF;
        std::copy(encrypted_premaster_secret.begin(), encrypted_premaster_secret.end(),
                payload.begin() + 2);
        return {
                HandshakeMessageType::ClientKeyExchange,
                payload
        };
    }
};

HandshakeMessage build_key_exchange_payload(
        const SignedX509Certificate &certificate,
        const std::array<unsigned char, 48> &premaster_key)
{
    if (certificate.tbs_certificate.subject_public_key.algorithm.type != AlgorithmType::Rsa)
    {
        throw std::runtime_error("tls error: unexpected server public key algorithm");
    }
    const auto key_asn = parse_asn1(certificate.tbs_certificate.subject_public_key.key);
    if (!std::holds_alternative<std::vector<Asn1>>(key_asn.data))
    {
        throw std::runtime_error("tls error: malformed public key");
    }
    const auto modulus_exp = std::get<std::vector<Asn1>>(key_asn.data);
    if (modulus_exp.size() != 2
        || !std::holds_alternative<BigNumber>(modulus_exp.at(0).data)
        || !std::holds_alternative<BigNumber>(modulus_exp.at(1).data))
    {
        throw std::runtime_error("tls error: malformed public key structure");
    }
    const auto premaster_encrypted = rsa_encrypt({ premaster_key.begin(), premaster_key.end() },
            std::get<BigNumber>(modulus_exp[1].data),
            std::get<BigNumber>(modulus_exp[0].data));
    return HandshakeClientKeyExchangePayload{ premaster_encrypted }.to_handshake_message();
}

struct CipherKeys
{
    std::vector<unsigned char> client_mac_secret;
    std::vector<unsigned char> server_mac_secret;
    std::array<unsigned char, 16> client_key;
    std::array<unsigned char, 16> server_key;
    std::array<unsigned char, 16> client_iv;
    std::array<unsigned char, 16> server_iv;
};

CipherKeys compute_cipher_keys(
        const std::vector<unsigned char> &master_secret,
        const std::array<unsigned char, 32> &client_random,
        const std::array<unsigned char, 32> server_random)
{
    int key_size = 20 * 2 + 16 * 2 + 16 * 2;
    const auto keys = compute_key_expansion(master_secret, client_random, server_random, key_size);
    std::vector<unsigned char> client_mac_secret(20);
    std::copy_n(keys.begin(), client_mac_secret.size(), client_mac_secret.begin());
    std::vector<unsigned char> server_mac_secret(20);
    std::copy_n(keys.begin() + 20, server_mac_secret.size(), server_mac_secret.begin());
    std::array<unsigned char, 16> client_key{};
    std::copy_n(keys.begin() + 40, client_key.size(), client_key.begin());
    std::array<unsigned char, 16> server_key{};
    std::copy_n(keys.begin() + 56, server_key.size(), server_key.begin());
    std::array<unsigned char, 16> client_iv{};
    std::copy_n(keys.begin() + 72, client_iv.size(), client_iv.begin());
    std::array<unsigned char, 16> server_iv{};
    std::copy_n(keys.begin() + 88, server_iv.size(), server_iv.begin());
    return {
            client_mac_secret,
            server_mac_secret,
            client_key,
            server_key,
            client_iv,
            server_iv,
    };
}

std::vector<HandshakeMessage> parse_server_handshake(const TlsRecord &record, HandshakeHashing &handshake_hashing)
{
    if (record.content_type != TlsRecordType::Handshake)
    {
        throw std::runtime_error("tls error: expected handshake message");
    }
    std::vector<HandshakeMessage> result{};
    size_t pos{};
    while (pos < record.payload.size())
    {
        const auto handshake_type = static_cast<HandshakeMessageType>(record.payload.at(pos++));
        const auto handshake_length =
                record.payload.at(pos) << 16 | record.payload.at(pos + 1) << 8 |
                record.payload.at(pos + 2);
        pos += 3;
        std::vector<unsigned char> handshake_payload{ record.payload.begin() + pos,
                                                      record.payload.begin() + pos + handshake_length };
        handshake_hashing.append({ record.payload.begin() + pos - 4, record.payload.begin() + pos + handshake_length });
        result.emplace_back(handshake_type, handshake_payload);
        pos += handshake_length;
    }
    return result;
}

struct ServerHelloData
{
    ServerHello server_hello;
    std::vector<SignedX509Certificate> certificate_chain;
};

ServerHelloData wait_server_hello_done(auto record_read, HandshakeHashing &handshake_hashing)
{
    ServerHello server_hello{};
    std::vector<SignedX509Certificate> certificate_chain{};
    while (true)
    {
        TlsRecord record = record_read();
        const auto messages = parse_server_handshake(record, handshake_hashing);
        for (const auto &handshake_message: messages)
        {
            if (handshake_message.type == HandshakeMessageType::ServerHello)
            {
                server_hello = parse_server_hello(handshake_message.payload.begin(), handshake_message.payload.end());
            }
            else if (handshake_message.type == HandshakeMessageType::Certificate)
            {
                certificate_chain = parse_x509_certificate_chain(handshake_message.payload.begin(),
                        handshake_message.payload.end());
            }
            else if (handshake_message.type == HandshakeMessageType::ServerHelloDone)
            {
                return { server_hello, certificate_chain };
            }
            else
            {
                throw std::runtime_error("tls error: server_hello expected");
            }
        }
    }
}

void TlsTcpSocket::connect(const Uri &uri)
{
    try
    {
        TcpSocket::connect(uri);
        const auto client_hello = HandshakeClientHelloPayload();
        send_tls_record({
                TlsRecordType::Handshake,
                tls1_0_version,
                client_hello.to_handshake_message().serialise()
        });

        const auto hello_reply = wait_server_hello_done([&]()
        {
            return read_tls_record();
        }, handshake_hashing);
        if (hello_reply.certificate_chain.empty() || hello_reply.server_hello.protocol_version != tls1_0_version)
        {
            throw std::runtime_error("tls error: malformed server hello");
        }
        switch (hello_reply.server_hello.cipher_suite_type)
        {
        case CipherSuiteType::TLS_RSA_WITH_AES_128_CBC_SHA:
        {
            std::array<unsigned char, 48> premaster_secret{ 3, 1, 33 };

            send_tls_record({
                    TlsRecordType::Handshake,
                    tls1_0_version,
                    build_key_exchange_payload(hello_reply.certificate_chain.at(0), premaster_secret).serialise()
            });
            send_tls_record({
                    TlsRecordType::ChangeCipherSpec,
                    tls1_0_version,
                    { 1 }
            });

            const auto master_secret = compute_master_secret(premaster_secret, client_hello.random_bytes,
                    hello_reply.server_hello.random);
            const auto cipher_keys = compute_cipher_keys(master_secret, client_hello.random_bytes,
                    hello_reply.server_hello.random);

            send_record_mac = TlsRecordMac{ cipher_keys.client_mac_secret };
            send_cipher_suite = std::make_unique<Aes128CipherSuite>(cipher_keys.client_iv, cipher_keys.client_key);

            const auto client_finished_message = HandshakeMessage{
                    HandshakeMessageType::Finished,
                    handshake_hashing.compute_finished_hash(master_secret, "client finished")
            };

            send_tls_record({
                    TlsRecordType::Handshake,
                    tls1_0_version,
                    client_finished_message.serialise()
            });

            auto record = read_tls_record();
            if (record.content_type == TlsRecordType::ChangeCipherSpec)
            {
                if (record.payload != std::vector<unsigned char>{ 1 })
                {
                    throw std::runtime_error("tls error: unexpected server change cipher message");
                }
            }
            else
            {
                throw std::runtime_error("tls error: server change cipher expected");
            }
            receive_record_mac = TlsRecordMac{ cipher_keys.server_mac_secret };
            receive_cipher_suite = std::make_unique<Aes128CipherSuite>(cipher_keys.server_iv, cipher_keys.server_key);
            record = read_tls_record();
            const auto expected_mac = handshake_hashing.compute_finished_hash(master_secret, "server finished");
            const auto server_finished = parse_server_handshake(record, handshake_hashing);
            if (server_finished.size() != 1 || server_finished[0].type != HandshakeMessageType::Finished)
            {
                throw std::runtime_error("tls error: server finished expected");
            }
            if (record.payload.size() != 4 + expected_mac.size() ||
                static_cast<HandshakeMessageType>(record.payload[0]) != HandshakeMessageType::Finished)
            {
                throw std::runtime_error("tls error: malformed server finished message");
            }
            if (expected_mac != server_finished[0].payload)
            {
                throw std::runtime_error("tls error: verify data missmatch");
            }
            break;
        }
        default:
            throw std::runtime_error("tls error: unexpected cipher suite requested");
        }
    }
    catch (const std::runtime_error &e)
    {
        close();
        throw e;
    }
}

int TlsTcpSocket::default_port()
{
    return 443;
}

void TlsTcpSocket::send_tls_record(TlsRecord tls_record)
{
    if (tls_record.content_type == TlsRecordType::Handshake)
    {
        handshake_hashing.append(tls_record.payload);
    }
    if (send_record_mac.has_value())
    {
        send_record_mac->append_mac(tls_record);
    }
    send_cipher_suite->encrypt(tls_record);
    TcpSocket::write(tls_record.serialise());
}

TlsRecord TlsTcpSocket::read_tls_record()
{
    std::vector<char> header_buffer(5, 0);
    std::vector<char> payload_buffer{};
    while (true)
    {
        TcpSocket::read(header_buffer);

        if (header_buffer.at(0) < static_cast<char>(TlsRecordType::ChangeCipherSpec) ||
            header_buffer.at(0) > static_cast<char>(TlsRecordType::ApplicationData))
        {
            close();
            throw std::runtime_error("tls error: response is not a valid TLS message");
        }
        TlsRecord server_package{};
        server_package.content_type = static_cast<TlsRecordType>(header_buffer.at(0));
        server_package.protocol_version = { header_buffer.at(1), header_buffer.at(2) };
        payload_buffer.resize((header_buffer.at(3) & 0xFF) << 8
                              | ((header_buffer.at(4) & 0xFF) << 0));
        TcpSocket::read(payload_buffer);
        server_package.payload = { payload_buffer.begin(), payload_buffer.end() };

        receive_cipher_suite->decrypt(server_package);
        if (receive_record_mac.has_value())
        {
            receive_record_mac->verify_and_clear_mac(server_package);
        }

        if (server_package.content_type == TlsRecordType::Alert)
        {
            const auto alert_level = server_package.payload.at(0);
            const auto alert_type = server_package.payload.at(1);
            if (alert_level == 2)
            {
                throw std::runtime_error("tls error: received fatal alert " + std::to_string(alert_type));
            }
            else
            {
                std::cerr << "Received non-fatal tls alert: " << alert_type;
            }
        }
        else
        {
            return server_package;
        }
    }
}

void TlsTcpSocket::write(const std::vector<char> &bytes)
{
    try
    {
        send_tls_record({
                TlsRecordType::ApplicationData,
                tls1_0_version,
                { bytes.begin(), bytes.end() }
        });
    }
    catch (std::runtime_error &ex)
    {
        close();
        throw std::runtime_error("failed to write to tls socket");
    }
}

std::vector<char> TlsTcpSocket::read()
{
    std::vector<char> buffer{};
    while (true)
    {
        try
        {
            const auto record = read_tls_record();
            if (record.content_type != TlsRecordType::ApplicationData)
            {
                throw std::runtime_error("application data expected");
            }
            std::copy(record.payload.begin(), record.payload.end(), std::back_inserter(buffer));
        }
        catch (std::runtime_error &e)
        {
            close();
            return buffer;
        }
    }
}
