#pragma once

# include <string>
# include "webserv.hpp"
# include "Configuration.hpp"
# include "Result.hpp"

class Socket {
 public:
	explicit Socket(const std::string &ip_addr, const std::string &port);
	~Socket();

    Socket();
    Socket(const Socket &other);
    Socket &operator=(const Socket &rhs);

	int	get_socket_fd() const;
	Result<int, std::string> get_socket_result() const;
	bool is_socket_success() const;

 private:
	Result<int, std::string> result_;
	int socket_fd_;
	struct addrinfo *addr_info_;
	std::string server_ip_;  // Nullable?
	std::string server_port_;

	Result<int, std::string> init_addr_info();
	Result<int, std::string> create_socket();
	Result<int, std::string> bind_socket() const;
	Result<int, std::string> listen_socket() const;
	Result<int, std::string> set_fd_to_nonblock() const;
};
