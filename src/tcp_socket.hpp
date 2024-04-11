#ifndef TLS_PLAYGROUND_TCP_SOCKET_HPP
#define TLS_PLAYGROUND_TCP_SOCKET_HPP

#include <vector>

#include "uri.hpp"

class TcpSocket
{
    int socket_fd{ -1 };

protected:
    void read(std::vector<char> &buffer);

    virtual int default_port();

public:
    TcpSocket() = default;

    TcpSocket(const TcpSocket &) = delete;

    TcpSocket(TcpSocket &&other) noexcept;

    virtual ~TcpSocket();

    TcpSocket &operator=(const TcpSocket &) = delete;

    TcpSocket &operator=(TcpSocket &&) noexcept;

    virtual void connect(const Uri &uri);

    virtual std::vector<char> read();

    virtual void write(const std::vector<char> &bytes);

    virtual void close();
};

#endif //TLS_PLAYGROUND_TCP_SOCKET_HPP
