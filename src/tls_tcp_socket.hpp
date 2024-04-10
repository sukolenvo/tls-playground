#ifndef TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "cipher_suite.hpp"
#include "handshake_hashing.hpp"
#include "tcp_socket.hpp"
#include "tls_record_mac.hpp"

class TlsTcpSocket : public TcpSocket
{
	HandshakeHashing handshake_hashing{};
	std::optional<TlsRecordMac> send_record_mac = std::nullopt;
	std::optional<TlsRecordMac> receive_record_mac = std::nullopt;
	std::unique_ptr<CipherSuite> send_cipher_suite = std::make_unique<NullCipherSuite>();
	std::unique_ptr<CipherSuite> receive_cipher_suite = std::make_unique<NullCipherSuite>();

	void send_tls_record(TlsRecord tls_record);

	TlsRecord read_tls_record();

protected:
	int default_port() override;

public:

	void connect(const Uri &uri) override;

	void write(const std::vector<char> &bytes) override;

	std::vector<char> read() override;
};

#endif //TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
