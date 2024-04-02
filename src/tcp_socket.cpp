#include <algorithm>
#include <array>
#include <stdexcept>
#include <utility>

#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "tcp_socket.hpp"

void TcpSocket::connect(const Uri &uri)
{
	if (socket_fd != -1)
	{
		throw std::runtime_error("socket already connected");
	}
	auto new_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (new_socket == -1)
	{
		throw std::runtime_error("Failed to create socket");
	}

	const auto host_result = gethostbyname(uri.host.c_str());
	if (host_result == nullptr)
	{
		switch (h_errno)
		{
		case HOST_NOT_FOUND:
			throw std::runtime_error("invalid hostname: host not found");
		case NO_ADDRESS:
			throw std::runtime_error("invalid hostname: no address");
		case TRY_AGAIN:
			throw std::runtime_error("invalid hostname: name server is temporary unavailable");
		default:
			throw std::runtime_error("invalid hostname: unknown error");
		}
	}
	sockaddr_in address{};
	address.sin_family = AF_INET;
	address.sin_addr = *reinterpret_cast<in_addr*>(host_result->h_addr_list[0]);
	address.sin_port = htons(uri.port.value_or(80));

	if (::connect(new_socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
	{
		throw std::runtime_error("Failed to connect");
	}
	socket_fd = new_socket;
}

TcpSocket::TcpSocket(TcpSocket &&other) noexcept : socket_fd(std::exchange(other.socket_fd, -1))
{
}

TcpSocket::~TcpSocket()
{
	if (socket_fd != -1) {
		close();
	}
}

TcpSocket &TcpSocket::operator=(TcpSocket &&other) noexcept
{
	std::swap(socket_fd, other.socket_fd);
	return *this;
}

std::vector<char> TcpSocket::read()
{
	if (socket_fd == -1)
	{
		throw std::runtime_error("failed to read: socket is not connected");
	}
	std::vector<char> result{};
	int received{};
	std::array<char, 2048> buffer{};
	while ((received = recv(socket_fd, buffer.data(), buffer.size(), 0)) > 0)
	{
		std::copy_n(buffer.begin(), received, std::back_inserter(result));
	}
	return result;
}

void TcpSocket::write(const std::string &bytes)
{
	if (socket_fd == -1)
	{
		throw std::runtime_error("failed to write: socket is not connected");
	}
	if (send(socket_fd, bytes.data(), bytes.length(), 0) == -1)
	{
		close();
		throw std::runtime_error("Failed to write into the socket");
	}
}

void TcpSocket::close()
{
	if (socket_fd != -1)
	{
		::close(socket_fd);
		socket_fd = -1;
	}
}
