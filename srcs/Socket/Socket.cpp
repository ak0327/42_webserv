#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include "Error.hpp"
#include "Socket.hpp"

namespace {
	int INIT_FD = -1;

	int OK = 0;
	int GETADDRINFO_SUCCESS = 0;

	int BIND_ERROR = -1;
	int CLOSE_ERROR = -1;
	int FCNTL_ERROR = -1;
	int LISTEN_ERROR = -1;
	int SETSOCKOPT_ERROR = -1;
	int SOCKET_ERROR = -1;

	void set_hints(struct addrinfo *hints) {
		hints->ai_socktype = SOCK_STREAM;
		hints->ai_family = AF_UNSPEC;  // allows IPv4 and IPv6
		hints->ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;  // socket, IP, PORT
		hints->ai_protocol = IPPROTO_TCP;
	}

	Result<int, std::string> set_socket_opt(int socket_fd) {
		const int		opt_val = 1;
		const socklen_t	opt_len = sizeof(opt_val);

		errno = 0;
		if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, opt_len) == SETSOCKOPT_ERROR) {
			std::string err_info = create_error_info(errno, __FILE__, __LINE__);
			return Result<int, std::string>::err(err_info);
		}
		return Result<int, std::string>::ok(OK);
	}

	Result<int, std::string> close_socket_fd(int socket_fd) {
		errno = 0;
		if (close(socket_fd) == CLOSE_ERROR) {
			std::string err_info = create_error_info(errno, __FILE__, __LINE__);
			return Result<int, std::string>::err(err_info);
		}
		return Result<int, std::string>::ok(OK);
	}
}  // namespace

Socket::Socket(const char *server_ip,
			   const char *server_port) : _result(),
			   							  _socket_fd(INIT_FD),
										  _addr_info(NULL),
										  _server_ip(server_ip),
										  _server_port(server_port) {
	this->_result = init_addr_info();
	if (this->_result.is_err()) {
		return;
	}
	this->_result = create_socket();
	if (this->_result.is_err()) {
		return;
	}
	this->_result = bind_socket();
	if (this->_result.is_err()) {
		return;
	}
	this->_result = listen_socket();
	if (this->_result.is_err()) {
		return;
	}
	this->_result = set_fd_to_nonblock();
	if (this->_result.is_err()) {
		return;
	}
}

// todo
// Socket::Socket(const Config &conf) {}

Socket::~Socket() {
	Result<int, std::string> close_result;

	if (this->_addr_info != NULL) {
		freeaddrinfo(this->_addr_info);
		this->_addr_info = NULL;
	}
	if (this->_socket_fd != INIT_FD) {
		close_result = close_socket_fd(this->_socket_fd);
		if (close_result.is_err()) {
			std::cerr << "close:" << close_result.get_err_value() << std::endl;
		}
		this->_socket_fd = INIT_FD;
	}
}

Result<int, std::string> Socket::init_addr_info() {
	struct addrinfo	hints = {};
	int				errcode;
	struct addrinfo	*ret_addr_info;

	set_hints(&hints);  // todo: setting IPv4, IPv6 from config??
	errcode = getaddrinfo(this->_server_ip, this->_server_port, &hints, &ret_addr_info);
	if (errcode != GETADDRINFO_SUCCESS) {
		std::string err_info = create_error_info(gai_strerror(errcode), __FILE__, __LINE__);
		return Result<int, std::string>::err("getaddrinfo:" + err_info);
	}
	this->_addr_info = ret_addr_info;
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::create_socket() {
	const int	ai_family = this->_addr_info->ai_family;
	const int	ai_socktype = this->_addr_info->ai_socktype;
	const int	ai_protocol = this->_addr_info->ai_protocol;
	int			socket_fd;

	errno = 0;
	socket_fd = socket(ai_family, ai_socktype, ai_protocol);
	if (socket_fd == SOCKET_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("socket:" + err_info);
	}
	this->_socket_fd = socket_fd;
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::bind_socket() const {
	Result<int, std::string>	set_opt_result;
	const struct sockaddr		*ai_addr = this->_addr_info->ai_addr;
	const socklen_t				ai_addrlen = this->_addr_info->ai_addrlen;

	set_opt_result = set_socket_opt(this->_socket_fd);
	if (set_opt_result.is_err()) {
		return set_opt_result;
	}

	errno = 0;
	if (bind(this->_socket_fd, ai_addr, ai_addrlen) == BIND_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("bind:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::listen_socket() const {
	errno = 0;
	if (listen(this->_socket_fd, SOMAXCONN) == LISTEN_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("listen:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::set_fd_to_nonblock() const {
	errno = 0;
	if (fcntl(this->_socket_fd, F_SETFL, O_NONBLOCK | FD_CLOEXEC) == FCNTL_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("fcntl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

int Socket::get_socket_fd() const { return this->_socket_fd; }
Result<int, std::string> Socket::get_socket_result() const { return this->_result; }
bool Socket::is_socket_success() const { return this->_result.is_ok(); }
