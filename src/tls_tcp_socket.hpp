#ifndef TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include "cipher_suite.hpp"
#include "handshake_hashing.hpp"
#include "md5.hpp"
#include "sha.hpp"
#include "tcp_socket.hpp"
#include "tls_record_mac.hpp"

class TlsTcpSocket : public TcpSocket
{
private:
	HandshakeHashing handshake_hashing{};
	std::optional<TlsRecordMac> send_record_mac = std::nullopt;
	std::optional<TlsRecordMac> receive_record_mac = std::nullopt;
	std::unique_ptr<CipherSuite> send_cipher_suite = std::make_unique<NullCipherSuite>();
	std::unique_ptr<CipherSuite> receive_cipher_suite = std::make_unique<NullCipherSuite>();
	struct ServerHelloData;
	ServerHelloData wait_server_done();
	void wait_server_change_cipher_spec();
	void wait_server_finished(const std::vector<unsigned char> &expected_mac);
protected:
	int default_port() override;
public:

	void connect(const Uri &uri) override;
};

#endif //TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
