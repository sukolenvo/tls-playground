#ifndef TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP

#include <functional>
#include <vector>

#include "md5.hpp"
#include "sha.hpp"
#include "tcp_socket.hpp"

struct TlsSuite {
	std::function<std::vector<unsigned char>(const std::vector<char> &payload)> decrypt;
};

class TlsTcpSocket : public TcpSocket
{
private:
	TlsSuite receive_suite;
	struct ServerHelloData;
	ServerHelloData wait_server_done(Sha1Hashing &handshake_hashing, Md5Hashing &md5_hashing);
	void wait_server_change_cipher_spec();
	void wait_server_finished(const std::vector<unsigned char> &expected_mac);
protected:
	int default_port() override;
public:

	void connect(const Uri &uri) override;
};

#endif //TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
