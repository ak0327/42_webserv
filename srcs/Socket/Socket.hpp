#pragma once

# include <string>
# include "webserv.hpp"
# include "Configuration.hpp"
# include "Result.hpp"

class Socket {
 public:
	explicit Socket(const Configuration &config);
	~Socket();

	int	get_socket_fd() const;
	Result<int, std::string> get_socket_result() const;
	bool is_socket_success() const;

 private:
	Result<int, std::string> _result;
	int _socket_fd;
	struct addrinfo *_addr_info;
	std::string _server_ip;  // Nullable?
	std::string _server_port;

	Result<int, std::string> init_addr_info();
	Result<int, std::string> create_socket();
	Result<int, std::string> bind_socket() const;
	Result<int, std::string> listen_socket() const;
	Result<int, std::string> set_fd_to_nonblock() const;
};
