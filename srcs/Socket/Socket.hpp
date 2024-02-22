#pragma once

# include <string>
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
    static SocketResult accept(int socket_fd, struct sockaddr_storage *client_addr);

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
