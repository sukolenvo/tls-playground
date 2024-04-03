#include <memory>
#include <stdexcept>

#include "uri.hpp"
#include "tcp_socket.hpp"
#include "tls_tcp_socket.hpp"
#include "http_client.hpp"

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
	if (uri.protocol != "http" && uri.protocol != "https")
	{
		throw std::runtime_error("protocol not supported: " + uri.protocol);
	}
	const auto socket = uri.protocol == "https" ? std::make_unique<TlsTcpSocket>() : std::make_unique<TcpSocket>();
	socket->connect(uri);
	const auto request = build_request(uri);
	socket->write({ request.begin(), request.end() });
	return socket->read();
}
