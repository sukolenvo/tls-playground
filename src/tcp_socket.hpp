#ifndef TLS_PLAYGROUND_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCP_SOCKET_HPP

#include <vector>

#include "uri.hpp"

class TcpSocket
{
	int socket_fd{-1};
public:
	TcpSocket() = default;
	TcpSocket(const TcpSocket &) = delete;

	TcpSocket(TcpSocket &&other) noexcept ;

	~TcpSocket();

	TcpSocket &operator=(const TcpSocket &) = delete;

	TcpSocket &operator=(TcpSocket &&) noexcept ;

	void connect(const Uri &uri);

	std::vector<char> read();

	void write(const std::string&bytes);

	void close();
};

#endif //TLS_PLAYGROUND_TCP_SOCKET_HPP
