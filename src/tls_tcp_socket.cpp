#include <algorithm>
#include <array>
#include <chrono>
#include <iostream>
#include <variant>

#include "aes.hpp"
#include "asn1.hpp"
#include "hmac.hpp"
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
//	const auto seconds = std::chrono::seconds(0x66124b36);
	std::array<unsigned char, 32> random{};
	random[0] = static_cast<char>((seconds.count() >> 24) & 0xFF);
	random[1] = static_cast<char>((seconds.count() >> 16) & 0xFF);
	random[2] = static_cast<char>((seconds.count() >> 8) & 0xFF);
	random[3] = static_cast<char>((seconds.count() >> 0) & 0xFF);
	return {
			{ 3, 1 },
			random,
			"",
			{ /*CipherSuiteType::TLS_RSA_WITH_3DES_EDE_CBC_SHA, CipherSuiteType::TLS_RSA_WITH_DES_CBC_SHA,*/
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

struct TlsRecord
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

std::vector<char> build_tls_message(const TlsRecord &tlsPackage)
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

TlsTcpSocket::ServerHelloData TlsTcpSocket::wait_server_done(Sha1Hashing &handshake_hashing, Md5Hashing &md5_hashing)
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
		TlsRecord server_package{};
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
//				if (handshake_type == HandshakeMessageType::ServerHello)
//				{
//					std::array<unsigned char, 32> mock_server_random{ 0x66, 0x12, 0x90, 0x5c, 0x38, 0x30, 0x37, 0xae,
//																	  0x38, 0x92, 0x18, 0x4f,
//																	  0xd4, 0xcb, 0x06, 0xf4, 0xbe, 0x1b, 0xc7, 0x03,
//																	  0x6b, 0x05, 0x5d, 0xa9,
//																	  0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00 };
//					std::copy(mock_server_random.begin(), mock_server_random.end(),
//							server_package.payload.begin() + pos + 2);
//					std::copy(mock_server_random.begin(), mock_server_random.end(),
//							server_package.payload.begin() + pos + 2 + 32 + 1);
//				}
				const std::vector<unsigned char> hash_payload{ server_package.payload.begin() + pos - 4,
															   server_package.payload.begin() + pos + handshake_length };
				handshake_hashing.append(hash_payload);
				md5_hashing.append(hash_payload);
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
		TlsRecord server_package{};
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
	std::copy(package.encrypted_premaster_secret.begin(), package.encrypted_premaster_secret.end(),
			payload.begin() + 2);
	return payload;
}

void TlsTcpSocket::wait_server_finished(const std::vector<unsigned char> &expected_mac) {
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
		TlsRecord server_package{};
		server_package.content_type = static_cast<TlsContentType>(buffer.at(0));
		server_package.protocol_version = { buffer.at(1), buffer.at(2) };
		server_package.payload = std::vector<char>(
				(buffer.at(3) & 0xFF) << 8
				| ((buffer.at(4) & 0xFF) << 0));

		TcpSocket::read(server_package.payload);


		auto payload = receive_suite.decrypt(server_package.payload);

		if (server_package.content_type == TlsContentType::Handshake)
		{
			if (payload.size() != 4 + expected_mac.size() ||
				static_cast<HandshakeMessageType>(payload[0]) != HandshakeMessageType::Finished)
			{
				close();
				throw std::runtime_error("tls error: malformed server finished message");
			}
			if (!std::equal(expected_mac.begin(), expected_mac.end(), payload.begin() + 4)) {
				close();
				throw std::runtime_error("tls error: verify data missmatch");
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

void TlsTcpSocket::connect(const Uri &uri)
{
	receive_suite.decrypt = [](const auto &payload) -> std::vector<unsigned char> {
		return { payload.begin(), payload.end() };
	};
	Sha1Hashing handshake_hashing{};
	Md5Hashing md5_hashing{};
	auto write_handshake_message = [&](const auto &tls_message)
	{
		std::vector<unsigned char> hash_payload(tls_message.payload.begin(), tls_message.payload.end());
		handshake_hashing.append(hash_payload);
		md5_hashing.append(hash_payload);
		TcpSocket::write(build_tls_message(tls_message));
	};
	TcpSocket::connect(uri);
	const auto client_hello = build_client_hello();
	const auto handshake_message = build_tls_payload(HandshakeMessageType::ClientHello, serialise(client_hello));
	const TlsRecord tls_message{
			TlsContentType::Handshake,
			{ 3, 1 },
			handshake_message
	};
	write_handshake_message(tls_message);

	const auto hello_reply = wait_server_done(handshake_hashing, md5_hashing);
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
		const TlsRecord tls_message{
				TlsContentType::Handshake,
				{ 3, 1 },
				key_exchange_message
		};
		write_handshake_message(tls_message);

		const auto master_secret = compute_master_secret(premaster_secret, client_hello.random_bytes,
				hello_reply.server_hello.random);

		int key_size = 20 * 2 + 16 * 2 + 16 * 2;
		const auto keys = compute_key_expansion(master_secret, client_hello.random_bytes, hello_reply.server_hello.random, key_size);
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

		TcpSocket::write(build_tls_message({
				TlsContentType::ChangeCipherSpec,
				{ 3, 1 },
				{ 1 }
		}));

		std::vector<unsigned char> verify_data = compute_verify_data(master_secret,
				"client finished",
				Md5Hashing(md5_hashing).close(),
				Sha1Hashing(handshake_hashing).close());
		auto client_finished_message = build_tls_payload(HandshakeMessageType::Finished, { verify_data.begin(),
																								 verify_data.end() });
		std::vector<unsigned char> hash_payload(client_finished_message.begin(), client_finished_message.end());
		handshake_hashing.append(hash_payload);
		md5_hashing.append(hash_payload);

		std::vector<unsigned char> mac_buffer(8, 0); // seq_num 0
		mac_buffer.push_back(static_cast<unsigned char>(TlsContentType::Handshake));
		mac_buffer.push_back(3);
		mac_buffer.push_back(1);
		mac_buffer.push_back(static_cast<char>((client_finished_message.size() >> 8) & 0xFF));
		mac_buffer.push_back(static_cast<char>((client_finished_message.size() >> 0) & 0xFF));
		std::copy(client_finished_message.begin(), client_finished_message.end(), std::back_inserter(mac_buffer));
		const auto mac = hmac_sha1(mac_buffer, client_mac_secret);
		std::copy(mac.begin(), mac.end(), std::back_inserter(client_finished_message));
		auto padding = 16 - client_finished_message.size() % 16;
		client_finished_message.insert(client_finished_message.end(), padding, padding - 1);
		auto encrypted_payload = aes128_cbc_encrypt({ client_finished_message.begin(), client_finished_message.end() }, client_iv, client_key);
		TcpSocket::write(build_tls_message({
				TlsContentType::Handshake,
				{ 3, 1},
				{ encrypted_payload.begin(), encrypted_payload.end() }
		}));
		wait_server_change_cipher_spec();
		receive_suite.decrypt = [&](const auto &payload) -> std::vector<unsigned char> {
			std::vector<unsigned char> decrypted_block = aes128_cbc_decrypt({ payload.begin(), payload.end() }, server_iv, server_key);
			if (decrypted_block.size() < decrypted_block.back() + 21)
			{
				close();
				throw std::runtime_error("tls error: malformed payload");
			}
			// TODO check mac
			decrypted_block.resize(decrypted_block.size() - decrypted_block.back() - 21);
			return decrypted_block;
		};
		wait_server_finished(compute_verify_data(master_secret,
				"server finished",
				Md5Hashing(md5_hashing).close(),
				Sha1Hashing(handshake_hashing).close()));

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
