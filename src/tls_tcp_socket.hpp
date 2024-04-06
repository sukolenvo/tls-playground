#ifndef TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP

#include "tcp_socket.hpp"


class TlsTcpSocket : public TcpSocket
{
private:
	struct ServerHelloData;
	ServerHelloData wait_server_done();
	void wait_server_change_cipher_spec();
protected:
	int default_port() override;
public:

	void connect(const Uri &uri) override;
};

#endif //TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
