#pragma once

# include <string>
# include "webserv.hpp"
# include "Configuration.hpp"
# include "Result.hpp"

typedef Result<int, std::string> SocketResult;

class Socket {
 public:
	explicit Socket(const std::string &ip_addr, const std::string &port);
	~Socket();


	int	get_socket_fd() const;
	SocketResult get_socket_result() const;
	bool is_socket_success() const;

	SocketResult init();
	SocketResult bind();
	SocketResult listen();
    SocketResult connect();
	SocketResult set_fd_to_nonblock();
    static SocketResult accept(int socket_fd);

 private:
	SocketResult result_;
	int socket_fd_;
	struct addrinfo *addr_info_;
	std::string server_ip_;
	std::string server_port_;

	SocketResult init_addr_info();

    Socket();
    Socket(const Socket &other);
    Socket &operator=(const Socket &rhs);
};
