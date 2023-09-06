#pragma once

# define SERVER_IP		"127.0.0.1"
# define SERVER_PORT	"8080"

// todo: config -> port, protocol
// todo: signal
class Socket {
 public:
	Socket();
	Socket(const char *server_ip, const char *server_port);
	~Socket();
	// Socket(const Socket &copy);  // for debug
	// Socket &operator=(const Socket &rhs);  // for debug

	int	get_socket_fd() const;
	int	get_status() const;
	// std::string get_server_ip() const;  // for debug
	// std::string get_server_port() const;  // for debug

 private:
	int _status;
	int _socket_fd;
	struct addrinfo *_addr_info;
	const char *_server_ip;  // Nullable
	const char *_server_port;

	int create_socket();
	int bind_socket() const;
	int listen_socket() const;
	int set_fd_to_nonblock() const;

	static int set_addr_info(const char *ip, const char *port, struct addrinfo **result);
	static void set_addr_hints(struct addrinfo *hints);
	static int set_socket_opt(int socket_fd);
	static void close_socket_fd(int socket_fd);
};
