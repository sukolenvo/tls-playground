#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>

#include "x509.hpp"
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
	std::chrono::time_point<std::chrono::system_clock> time;
	std::array<unsigned char, 28> random_bytes;
	std::string session_id;
	std::vector<CipherSuiteType> cipher_suites;
	std::vector<CompressionType> compression_methods;
};


std::vector<char> serialise(const ClientHelloPackage &package)
{
	std::vector<char> buffer{};
	buffer.push_back(package.protocol_version.major);
	buffer.push_back(package.protocol_version.minor);
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(package.time.time_since_epoch());
	buffer.push_back(static_cast<char>((seconds.count() >> 24) & 0xFF));
	buffer.push_back(static_cast<char>((seconds.count() >> 16) & 0xFF));
	buffer.push_back(static_cast<char>((seconds.count() >> 8) & 0xFF));
	buffer.push_back(static_cast<char>((seconds.count() >> 0) & 0xFF));
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
	return {
			{ 3, 1 },
			std::chrono::system_clock::now(),
			{},
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
	std::array<char, 32> random;
	std::string session;
	CipherSuiteType cipher_suite_type;
	CompressionType compression_type;
};

ServerHello parse_server_hello(auto begin, const auto end)
{
	const auto major = *begin++;
	const auto minor = *begin++;
	std::array<char, 32> random{};
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

	const auto hello_data = wait_server_done();
	if (hello_data.certificate_chain.empty() || hello_data.server_hello.protocol_version != ProtocolVersion{ 3, 1 })
	{
		close();
		throw std::runtime_error("tls error: malformed server hello");
	}
}

int TlsTcpSocket::default_port()
{
	return 443;
}
