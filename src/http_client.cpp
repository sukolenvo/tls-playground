#include <algorithm>
#include <array>
#include <stdexcept>
#include <string>
#include <vector>

#include "uri.hpp"
#include "tcp_socket.hpp"
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
	if (uri.protocol != "http")
	{
		throw std::runtime_error("protocol not supported: " + uri.protocol);
	}
	TcpSocket socket{};
	socket.connect(uri);
	socket.write(build_request(uri));
	return socket.read();
}
