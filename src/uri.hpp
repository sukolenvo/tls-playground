#ifndef TLS_PLAYGROUND_URI_HPP
#define TLS_PLAYGROUND_URI_HPP

#include <optional>
#include <ostream>
#include <string>

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

#endif //TLS_PLAYGROUND_URI_HPP
