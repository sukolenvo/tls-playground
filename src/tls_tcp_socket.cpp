#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <variant>

#include "asn1.hpp"
#include "rsa.hpp"
#include "x509.hpp"
#include "tls_prf.hpp"
#include "tls_tcp_socket.hpp"

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

struct ProtocolVersion
{
	char major, minor;

	int operator<=>(const ProtocolVersion &other) const = default;
};

struct ClientHelloPackage
{
	ProtocolVersion protocol_version;
	std::array<unsigned char, 32> random_bytes;
	std::string session_id;
	std::vector<CipherSuiteType> cipher_suites;
	std::vector<CompressionType> compression_methods;
};


std::vector<char> serialise(const ClientHelloPackage &package)
{
	std::vector<char> buffer{};
	buffer.push_back(package.protocol_version.major);
	buffer.push_back(package.protocol_version.minor);
	std::copy(package.random_bytes.begin(), package.random_bytes.end(), std::back_inserter(buffer));
	buffer.push_back(package.session_id.size());
	std::copy(package.session_id.begin(), package.session_id.end(), std::back_inserter(buffer));
	const auto cipher_field_length = package.cipher_suites.size() * 2;
	buffer.push_back((cipher_field_length >> 8) & 0xFF);
	buffer.push_back((cipher_field_length) & 0xFF);
	for (const auto cipher_suite: package.cipher_suites)
	{
		buffer.push_back((static_cast<unsigned int>(cipher_suite) >> 8) & 0xFF);
		buffer.push_back((static_cast<unsigned int>(cipher_suite) >> 0) & 0xFF);
	}
	buffer.push_back(package.compression_methods.size());
	for (const auto compression: package.compression_methods)
	{
		buffer.push_back(static_cast<char>(compression));
	}
	return buffer;
}

ClientHelloPackage build_client_hello()
{
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch());
	std::array<unsigned char, 32> random{};
	random[0] = static_cast<char>((seconds.count() >> 24) & 0xFF);
	random[0] = static_cast<char>((seconds.count() >> 16) & 0xFF);
	random[0] = static_cast<char>((seconds.count() >> 8) & 0xFF);
	random[0] = static_cast<char>((seconds.count() >> 0) & 0xFF);
	return {
			{ 3, 1 },
			random,
			"",
			{ CipherSuiteType::TLS_RSA_WITH_3DES_EDE_CBC_SHA, CipherSuiteType::TLS_RSA_WITH_DES_CBC_SHA,
			  CipherSuiteType::TLS_RSA_WITH_AES_128_CBC_SHA },
			{ CompressionType::NONE }
	};
}

enum class TlsContentType : char
{
	ChangeCipherSpec = 20,
	Alert = 21,
	Handshake = 22,
	ApplicationData = 23
};

struct TlsPackage
{
	TlsContentType content_type;
	ProtocolVersion protocol_version;
	std::vector<char> payload;
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

std::vector<char> build_tls_payload(const HandshakeMessageType &packageType, const std::vector<char> &package)
{
	std::vector<char> result{};
	result.push_back(static_cast<char>(packageType));
	result.push_back(static_cast<char>((package.size() >> 16) & 0xFF));
	result.push_back(static_cast<char>((package.size() >> 8) & 0xFF));
	result.push_back(static_cast<char>((package.size() >> 0) & 0xFF));
	std::copy(package.begin(), package.end(), std::back_inserter(result));
	return result;
}

std::vector<char> build_tls_message(const TlsPackage &tlsPackage)
{
	std::vector<char> result{};
	result.push_back(static_cast<char>(tlsPackage.content_type));
	result.push_back(tlsPackage.protocol_version.major);
	result.push_back(tlsPackage.protocol_version.minor);
	result.push_back(static_cast<char>((tlsPackage.payload.size() >> 8) & 0xFF));
	result.push_back(static_cast<char>((tlsPackage.payload.size() >> 0) & 0xFF));
	std::copy(tlsPackage.payload.begin(), tlsPackage.payload.end(), std::back_inserter(result));
	return result;
}

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
	const auto major = *begin++;
	const auto minor = *begin++;
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

struct TlsTcpSocket::ServerHelloData
{
	ServerHello server_hello;
	std::vector<SignedX509Certificate> certificate_chain;
};

TlsTcpSocket::ServerHelloData TlsTcpSocket::wait_server_done()
{
	ServerHello server_hello{};
	std::vector<SignedX509Certificate> certificate_chain{};
	std::vector<char> buffer(5, 0);
	while (true)
	{
		TcpSocket::read(buffer);

		if (buffer.at(0) < static_cast<char>(TlsContentType::ChangeCipherSpec) ||
			buffer.at(0) > static_cast<char>(TlsContentType::ApplicationData))
		{
			close();
			throw std::runtime_error("tls error: response is not a valid TLS message");
		}
		TlsPackage server_package{};
		server_package.content_type = static_cast<TlsContentType>(buffer.at(0));
		server_package.protocol_version = { buffer.at(1), buffer.at(2) };
		server_package.payload = std::vector<char>(
				(buffer.at(3) & 0xFF) << 8
				| ((buffer.at(4) & 0xFF) << 0));

		TcpSocket::read(server_package.payload);

		if (server_package.content_type == TlsContentType::Handshake)
		{
			size_t pos{};
			while (pos < server_package.payload.size())
			{
				const auto handshake_type = static_cast<HandshakeMessageType>(server_package.payload.at(pos++));
				const auto handshake_length =
						server_package.payload.at(pos) << 16 | server_package.payload.at(pos + 1) << 8 |
						server_package.payload.at(pos + 2);
				pos += 3;
				if (handshake_type == HandshakeMessageType::ServerHello)
				{
					server_hello = parse_server_hello(server_package.payload.begin() + pos,
							server_package.payload.begin() + pos + handshake_length);
					pos += handshake_length;
				}
				else if (handshake_type == HandshakeMessageType::Certificate)
				{
					certificate_chain = parse_x509_certificate_chain(server_package.payload.begin() + pos,
							server_package.payload.begin() + pos + handshake_length);
					pos += handshake_length;
				}
				else if (handshake_type == HandshakeMessageType::ServerHelloDone)
				{
					return { server_hello, certificate_chain };
				}
				else
				{
					close();
					throw std::runtime_error("tls error: server_hello expected");
				}
			}
		}
		else if (server_package.content_type == TlsContentType::Alert)
		{
			const auto alert_level = server_package.payload.at(0);
			const auto alert_type = server_package.payload.at(1);
			if (alert_level == 2)
			{
				close();
				throw std::runtime_error("tls error: received fatal alert " + std::to_string(alert_type));
			}
			else
			{
				std::cerr << "Received non-fatal tls alert: " << alert_type;
			}
		}
		else
		{
			close();
			throw std::runtime_error("tls error: handshake package expected");
		}
	}
}


void TlsTcpSocket::wait_server_change_cipher_spec()
{
	std::vector<char> buffer(5, 0);
	while (true)
	{
		TcpSocket::read(buffer);

		if (buffer.at(0) < static_cast<char>(TlsContentType::ChangeCipherSpec) ||
			buffer.at(0) > static_cast<char>(TlsContentType::ApplicationData))
		{
			close();
			throw std::runtime_error("tls error: response is not a valid TLS message");
		}
		TlsPackage server_package{};
		server_package.content_type = static_cast<TlsContentType>(buffer.at(0));
		server_package.protocol_version = { buffer.at(1), buffer.at(2) };
		server_package.payload = std::vector<char>(
				(buffer.at(3) & 0xFF) << 8
				| ((buffer.at(4) & 0xFF) << 0));

		TcpSocket::read(server_package.payload);

		if (server_package.content_type == TlsContentType::ChangeCipherSpec)
		{
			if (server_package.payload != std::vector<char>{ 1 })
			{
				close();
				throw std::runtime_error("tls error: unexpected server change cipher message");
			}
			return;
		}
		else if (server_package.content_type == TlsContentType::Alert)
		{
			const auto alert_level = server_package.payload.at(0);
			const auto alert_type = server_package.payload.at(1);
			if (alert_level == 2)
			{
				close();
				throw std::runtime_error("tls error: received fatal alert " + std::to_string(alert_type));
			}
			else
			{
				std::cerr << "Received non-fatal tls alert: " << alert_type;
			}
		}
		else
		{
			close();
			throw std::runtime_error("tls error: handshake package expected");
		}
	}
}

struct ClientKeyExchangePackage
{
	std::vector<unsigned char> encrypted_premaster_secret;
};

std::vector<char> serialise(const ClientKeyExchangePackage &package)
{
	std::vector<char> payload(package.encrypted_premaster_secret.size() + 2);
	payload[0] = (package.encrypted_premaster_secret.size() >> 8) & 0xFF;
	payload[1] = (package.encrypted_premaster_secret.size() >> 0) & 0xFF;
	std::copy(package.encrypted_premaster_secret.begin(), package.encrypted_premaster_secret.end(), payload.begin() + 2);
	return payload;
}

void TlsTcpSocket::connect(const Uri &uri)
{
	TcpSocket::connect(uri);
	const auto client_hello = build_client_hello();
	const auto handshake_message = build_tls_payload(HandshakeMessageType::ClientHello, serialise(client_hello));
	const TlsPackage tls_message{
			TlsContentType::Handshake,
			{ 3, 1 },
			handshake_message
	};
	TcpSocket::write(build_tls_message(tls_message));

	const auto hello_reply = wait_server_done();
	if (hello_reply.certificate_chain.empty() || hello_reply.server_hello.protocol_version != ProtocolVersion{ 3, 1 })
	{
		close();
		throw std::runtime_error("tls error: malformed server hello");
	}
	switch (hello_reply.server_hello.cipher_suite_type)
	{
	case CipherSuiteType::TLS_RSA_WITH_AES_128_CBC_SHA:
	{
		std::array<unsigned char, 48> premaster_secret{ 3, 1, 33 };
		if (hello_reply.certificate_chain.at(0).tbs_certificate.subject_public_key.algorithm.type != AlgorithmType::Rsa)
		{
			close();
			throw std::runtime_error("tls error: unexpected server public key algorithm");
		}
		const auto key_asn = parse_asn1(hello_reply.certificate_chain.at(0).tbs_certificate.subject_public_key.key);
		if (!std::holds_alternative<std::vector<Asn1>>(key_asn.data))
		{
			close();
			throw std::runtime_error("tls error: malformed public key");
		}
		const auto modulus_exp = std::get<std::vector<Asn1>>(key_asn.data);
		if (modulus_exp.size() != 2
			|| !std::holds_alternative<BigNumber>(modulus_exp.at(0).data)
			|| !std::holds_alternative<BigNumber>(modulus_exp.at(1).data))
		{
			close();
			throw std::runtime_error("tls error: malformed public key structure");
		}
		const auto premaster_encrypted = rsa_encrypt({ premaster_secret.begin(), premaster_secret.end() },
				std::get<BigNumber>(modulus_exp[1].data),
				std::get<BigNumber>(modulus_exp[0].data));
		const auto key_exchange_message = build_tls_payload(HandshakeMessageType::ClientKeyExchange,
				serialise({ premaster_encrypted }));
		const TlsPackage tls_message{
				TlsContentType::Handshake,
				{ 3, 1 },
				key_exchange_message
		};
		TcpSocket::write(build_tls_message(tls_message));

		const auto master_key = compute_master_secret(premaster_secret, client_hello.random_bytes, hello_reply.server_hello.random);

		// TODO expand master key

		TcpSocket::write(build_tls_message({
			TlsContentType::ChangeCipherSpec,
			{3, 1},
			{ 1 }
		}));

		wait_server_change_cipher_spec();


		break;
	}
	default:
		close();
		throw std::runtime_error("tls error: unexpected cipher suite requested");
	}
}

int TlsTcpSocket::default_port()
{
	return 443;
}