#pragma once

# include <string>
# include "Result.hpp"

class Socket {
 public:
	Socket(const char *server_ip, const char *server_port);
	// Socket(const Config &conf);
	~Socket();

	int	get_socket_fd() const;
	Result<int, std::string> get_socket_result() const;
	bool is_socket_success() const;

 private:
	Result<int, std::string> _result;
	int _socket_fd;
	struct addrinfo *_addr_info;
	const char *_server_ip;  // Nullable
	const char *_server_port;

	Result<int, std::string> init_addr_info();
	Result<int, std::string> create_socket();
	Result<int, std::string> bind_socket() const;
	Result<int, std::string> listen_socket() const;
	Result<int, std::string> set_fd_to_nonblock() const;
};
