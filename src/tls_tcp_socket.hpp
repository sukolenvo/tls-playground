#ifndef TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP

#include "tcp_socket.hpp"


class TlsTcpSocket : public TcpSocket
{
protected:
	int default_port() override;
public:

	void connect(const Uri &uri) override;
};

#endif //TLS_PLAYGROUND_TCL_TCP_SOCKET_HPP
