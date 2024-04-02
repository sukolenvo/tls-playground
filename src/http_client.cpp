#include <algorithm>
#include <array>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include "http_client.hpp"

Uri parse_url(const std::string &url)
{
	const auto protocol_end_idx = url.find("://");
	if (protocol_end_idx == std::string::npos)
	{
		throw std::runtime_error("malformed url: protocol missing");
	}
	const auto host_start_idx{ protocol_end_idx + 3 };
	auto host_end_idx = url.find('/', host_start_idx);
	if (host_end_idx == std::string::npos)
	{
		host_end_idx = url.size();
	}
	auto path_start_idx{host_end_idx};
	if (host_end_idx - host_start_idx == 0)
	{
		throw std::runtime_error("malformed url: host missing");
	}
	auto port_start_idx = url.find(':', host_start_idx);
	if (port_start_idx != std::string::npos && port_start_idx > host_end_idx)
	{
		port_start_idx = std::string::npos;
	}
	std::optional<int> port{};
	if (port_start_idx != std::string::npos)
	{
		port = std::stoi(url.substr(port_start_idx + 1, host_end_idx - port_start_idx));
		host_end_idx = port_start_idx;
	}
	return {
			url.substr(0, protocol_end_idx),
			url.substr(host_start_idx, host_end_idx - host_start_idx),
			port,
			path_start_idx == url.size() ? "/" : url.substr(path_start_idx, url.size() - path_start_idx)
	};
}

std::string build_request(const Uri &uri)
{
	return "GET " + uri.path + R"( HTTP/1.1
Host: localhost
User-agent: github/sukolenvo
Connection: close

)";
}

std::vector<char> http_get(const std::string &url)
{
	const auto uri = parse_url(url);
	if (uri.protocol != "http")
	{
		throw std::runtime_error("protocol not supported: " + uri.protocol);
	}
	auto sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (sock_fd == -1)
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

	if (connect(sock_fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
	{
		throw std::runtime_error("Failed to connect");
	}

	const std::string request = build_request(uri);
	if (send(sock_fd, request.data(), request.length(), 0) == -1)
	{
		close(sock_fd);
		throw std::runtime_error("Failed to write into the socket");
	}

	std::vector<char> result{};
	int received{};
	std::array<char, 2048> buffer{};
	while ((received = recv(sock_fd, buffer.data(), buffer.size(), 0)) > 0)
	{
		std::copy_n(buffer.begin(), received, std::back_inserter(result));
	}
	close(sock_fd);
	return result;
}

std::ostream &operator<<(std::ostream &stream, const Uri &it)
{
	return stream << "Uri{protocol=" << it.protocol << ", host=" << it.host
				  << ", port=" << (it.port.has_value() ? std::to_string(it.port.value()) : "")
				  << ", path=" << it.path
				  << '}';
}
