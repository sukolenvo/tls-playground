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

struct ClientHelloPackage
{
	ProtocolVersion protocol_version;
	std::array<unsigned char, 32> random_bytes;
	std::string session_id;
	std::vector<CipherSuiteType> cipher_suites;
	std::vector<CompressionType> compression_methods;
};


std::vector<unsigned char> serialise(const ClientHelloPackage &package)
{
	std::vector<unsigned char> buffer{};
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
		buffer.push_back(static_cast<unsigned char>(compression));
	}
	return buffer;
}

ClientHelloPackage build_client_hello()
{
	const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch());
	std::array<unsigned char, 32> random{};
	random[0] = static_cast<char>((seconds.count() >> 24) & 0xFF);
	random[1] = static_cast<char>((seconds.count() >> 16) & 0xFF);
	random[2] = static_cast<char>((seconds.count() >> 8) & 0xFF);
	random[3] = static_cast<char>((seconds.count() >> 0) & 0xFF);
	return {
			{ 3, 1 },
			random,
			"",
			{ CipherSuiteType::TLS_RSA_WITH_3DES_EDE_CBC_SHA, CipherSuiteType::TLS_RSA_WITH_DES_CBC_SHA,
			  CipherSuiteType::TLS_RSA_WITH_AES_128_CBC_SHA },
			{ CompressionType::NONE }
	};
}

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

std::vector<unsigned char> build_tls_payload(const HandshakeMessageType &packageType, const std::vector<unsigned char> &package)
{
	std::vector<unsigned char> result{};
	result.push_back(static_cast<unsigned char>(packageType));
	result.push_back(static_cast<unsigned char>((package.size() >> 16) & 0xFF));
	result.push_back(static_cast<unsigned char>((package.size() >> 8) & 0xFF));
	result.push_back(static_cast<unsigned char>((package.size() >> 0) & 0xFF));
	std::copy(package.begin(), package.end(), std::back_inserter(result));
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

struct TlsTcpSocket::ServerHelloData
{
	ServerHello server_hello;
	std::vector<SignedX509Certificate> certificate_chain;
};

TlsTcpSocket::ServerHelloData TlsTcpSocket::wait_server_done()
{
	ServerHello server_hello{};
	std::vector<SignedX509Certificate> certificate_chain{};
	std::vector<char> header_buffer(5);
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

		if (server_package.content_type == TlsRecordType::Handshake)
		{
			size_t pos{};
			while (pos < server_package.payload.size())
			{
				const auto handshake_type = static_cast<HandshakeMessageType>(server_package.payload.at(pos++));
				const auto handshake_length =
						server_package.payload.at(pos) << 16 | server_package.payload.at(pos + 1) << 8 |
						server_package.payload.at(pos + 2);
				pos += 3;
				handshake_hashing.append({ server_package.payload.begin() + pos - 4,
										   server_package.payload.begin() + pos + handshake_length });
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
		else if (server_package.content_type == TlsRecordType::Alert)
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
	std::vector<char> header_buffer(5);
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

		if (server_package.content_type == TlsRecordType::ChangeCipherSpec)
		{
			if (server_package.payload != std::vector<unsigned char>{ 1 })
			{
				close();
				throw std::runtime_error("tls error: unexpected server change cipher message");
			}
			return;
		}
		else if (server_package.content_type == TlsRecordType::Alert)
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

std::vector<unsigned char> serialise(const ClientKeyExchangePackage &package)
{
	std::vector<unsigned char> payload(package.encrypted_premaster_secret.size() + 2);
	payload[0] = (package.encrypted_premaster_secret.size() >> 8) & 0xFF;
	payload[1] = (package.encrypted_premaster_secret.size() >> 0) & 0xFF;
	std::copy(package.encrypted_premaster_secret.begin(), package.encrypted_premaster_secret.end(),
			payload.begin() + 2);
	return payload;
}

void TlsTcpSocket::wait_server_finished(const std::vector<unsigned char> &expected_mac) {
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
		receive_record_mac->verify_and_clear_mac(server_package);

		if (server_package.content_type == TlsRecordType::Handshake)
		{
			if (server_package.payload.size() != 4 + expected_mac.size() ||
				static_cast<HandshakeMessageType>(server_package.payload[0]) != HandshakeMessageType::Finished)
			{
				close();
				throw std::runtime_error("tls error: malformed server finished message");
			}
			if (!std::equal(expected_mac.begin(), expected_mac.end(), server_package.payload.begin() + 4)) {
				close();
				throw std::runtime_error("tls error: verify data missmatch");
			}
			return;

		}
		else if (server_package.content_type == TlsRecordType::Alert)
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

std::vector<unsigned char> build_key_exchange_payload(
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
	return build_tls_payload(HandshakeMessageType::ClientKeyExchange,
			serialise({ premaster_encrypted }));
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

void TlsTcpSocket::connect(const Uri &uri)
{
	try {
		auto send_tls_record = [&](TlsRecord tls_message)
		{
			if (tls_message.content_type == TlsRecordType::Handshake)
			{
				handshake_hashing.append(tls_message.payload);
			}
			if (send_record_mac.has_value()) {
				send_record_mac->append_mac(tls_message);
			}
			send_cipher_suite->encrypt(tls_message);
			TcpSocket::write(tls_message.serialise());
		};
		TcpSocket::connect(uri);
		const auto client_hello = build_client_hello();
		const auto client_hello_message = build_tls_payload(HandshakeMessageType::ClientHello, serialise(client_hello));
		send_tls_record({
				TlsRecordType::Handshake,
				tls1_0_version,
				client_hello_message
		});

		const auto hello_reply = wait_server_done();
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
					build_key_exchange_payload(hello_reply.certificate_chain.at(0), premaster_secret)
			});
			send_tls_record({
					TlsRecordType::ChangeCipherSpec,
					tls1_0_version,
					{ 1 }
			});

			const auto master_secret = compute_master_secret(premaster_secret, client_hello.random_bytes,
					hello_reply.server_hello.random);
			const auto cipher_keys = compute_cipher_keys(master_secret, client_hello.random_bytes, hello_reply.server_hello.random);

			send_record_mac = TlsRecordMac{ cipher_keys.client_mac_secret };
			send_cipher_suite = std::make_unique<Aes128CipherSuite>(cipher_keys.client_iv, cipher_keys.client_key);

			auto client_finished_message = build_tls_payload(
					HandshakeMessageType::Finished,
					handshake_hashing.compute_finished_hash(master_secret, "client finished"));

			send_tls_record({
					TlsRecordType::Handshake,
					tls1_0_version,
					client_finished_message
			});

			wait_server_change_cipher_spec();
			receive_record_mac = TlsRecordMac{ cipher_keys.server_mac_secret };
			receive_cipher_suite = std::make_unique<Aes128CipherSuite>(cipher_keys.server_iv, cipher_keys.server_key);
			wait_server_finished(handshake_hashing.compute_finished_hash(master_secret, "server finished"));
			break;
		}
		default:
			throw std::runtime_error("tls error: unexpected cipher suite requested");
		}
	} catch (const std::runtime_error &e)
	{
		close();
		throw e;
	}
}

int TlsTcpSocket::default_port()
{
	return 443;
}
