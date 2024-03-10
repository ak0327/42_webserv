#pragma once

# include <string>
# include <vector>
# include "webserv.hpp"
# include "Config.hpp"
# include "Result.hpp"

typedef Result<int, std::string> SocketResult;

class Socket {
 public:
	explicit Socket(const std::string &ip_addr, const std::string &port);
	~Socket();


	int	get_socket_fd() const;

    SocketResult create_socket();

    SocketResult init();
	SocketResult bind();
	SocketResult listen();
    SocketResult connect();
    SocketResult set_fd_to_nonblock();

    AddressPortPair get_server_listen();

    static SocketResult set_fd_to_keepalive(int fd);
	static SocketResult set_fd_to_nonblock(int fd);
    static SocketResult accept(int socket_fd, struct sockaddr_storage *client_addr);

    static Result<std::size_t, ErrMsg> recv(int fd, void *buf, std::size_t bufsize);
    static Result<ProcResult, ErrMsg> recv_to_buf(int fd, std::vector<unsigned char> *buf);

    static Result<std::size_t, ErrMsg> send(int fd, void *buf, std::size_t bufsize);
    static Result<ProcResult, ErrMsg> send_buf(int fd, std::vector<unsigned char> *buf);

 private:
	int socket_fd_;
	struct addrinfo *addr_info_;
	std::string server_ip_;
	std::string server_port_;

	SocketResult init_addr_info();

    Socket();
    Socket(const Socket &other);
    Socket &operator=(const Socket &rhs);
};
