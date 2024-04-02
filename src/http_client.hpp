#ifndef TLS_PLAYGROUND_HTTP_CLIENT_HPP
#define TLS_PLAYGROUND_HTTP_CLIENT_HPP

#include <optional>
#include <ostream>
#include <string>
#include <vector>

struct Uri
{
	std::string protocol;
	std::string host;
	std::optional<int> port;
	std::string path;

	int operator<=>(const Uri &other) const = default;

	friend std::ostream &operator<<(std::ostream &stream, const Uri &it);
};

Uri parse_url(const std::string &url);

std::vector<char> http_get(const std::string &url);

#endif //TLS_PLAYGROUND_HTTP_CLIENT_HPP
