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

	SocketResult init();
	SocketResult bind();
	SocketResult listen();
    SocketResult connect();
    SocketResult set_fd_to_nonblock();
	static SocketResult set_fd_to_nonblock(int fd);
    static SocketResult accept(int socket_fd, struct sockaddr_storage *client_addr);

    static ssize_t recv(int fd, void *buf, std::size_t bufsize);
    static ssize_t recv_to_buf(int fd, std::vector<unsigned char> *buf);
    static ssize_t send(int fd, void *buf, std::size_t bufsize);
    static ProcResult send_buf(int fd, std::vector<unsigned char> *buf);

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
