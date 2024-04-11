#include "uri.hpp"

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
    auto path_start_idx{ host_end_idx };
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

std::ostream &operator<<(std::ostream &stream, const Uri &it)
{
    return stream << "Uri{protocol=" << it.protocol << ", host=" << it.host
                  << ", port=" << (it.port.has_value() ? std::to_string(it.port.value()) : "")
                  << ", path=" << it.path
                  << '}';
}
