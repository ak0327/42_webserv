#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include "Color.hpp"
#include "Constant.hpp"
#include "Error.hpp"
#include "Socket.hpp"

namespace {

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

////////////////////////////////////////////////////////////////////////////////


Socket::Socket(const std::string &ip_addr, const std::string &port)
    : result_(),
      socket_fd_(INIT_FD),
      addr_info_(NULL),
      server_ip_(ip_addr),
      server_port_(port) {
	this->result_ = init_addr_info();
	if (this->result_.is_err()) {
		return;
	}
	this->result_ = create_socket();
	if (this->result_.is_err()) {
		return;
	}
	this->result_ = bind_socket();
	if (this->result_.is_err()) {
		return;
	}
	this->result_ = listen_socket();
	if (this->result_.is_err()) {
		return;
	}
	this->result_ = set_fd_to_nonblock();
	if (this->result_.is_err()) {
		return;
	}
}


Socket::~Socket() {
    // std::cout << CYAN << "~Socket called" << RESET << std::endl;
    if (this->addr_info_ != NULL) {
		freeaddrinfo(this->addr_info_);
		this->addr_info_ = NULL;
	}
	if (this->socket_fd_ != INIT_FD) {
        Result<int, std::string> close_result = close_socket_fd(this->socket_fd_);
		if (close_result.is_err()) {
			std::cerr << "close:" << close_result.get_err_value() << std::endl;
		}
		this->socket_fd_ = INIT_FD;
	}
}


Result<int, std::string> Socket::init_addr_info() {
	struct addrinfo	hints = {};
	struct addrinfo	*ret_addr_info;

	set_hints(&hints);  // todo: setting IPv4, IPv6 from config??
    const char *ip = (this->server_ip_ != "*") ? this->server_ip_.c_str() : NULL;
	int errcode = getaddrinfo(ip, this->server_port_.c_str(), &hints, &ret_addr_info);

	if (errcode != GETADDRINFO_SUCCESS) {
		std::string err_info = create_error_info(gai_strerror(errcode), __FILE__, __LINE__);
		return Result<int, std::string>::err("getaddrinfo:" + err_info);
	}
	this->addr_info_ = ret_addr_info;
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::create_socket() {
	const int	ai_family = this->addr_info_->ai_family;
	const int	ai_socktype = this->addr_info_->ai_socktype;
	const int	ai_protocol = this->addr_info_->ai_protocol;

	errno = 0;
	int socket_fd = socket(ai_family, ai_socktype, ai_protocol);
	if (socket_fd == SOCKET_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("socket:" + err_info);
	}
	this->socket_fd_ = socket_fd;
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::bind_socket() const {
	const struct sockaddr *ai_addr = this->addr_info_->ai_addr;
	const socklen_t ai_addrlen = this->addr_info_->ai_addrlen;

    Result<int, std::string> set_opt_result = set_socket_opt(this->socket_fd_);
	if (set_opt_result.is_err()) {
		return set_opt_result;
	}

	errno = 0;
	if (bind(this->socket_fd_, ai_addr, ai_addrlen) == BIND_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("bind:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::listen_socket() const {
	errno = 0;
	if (listen(this->socket_fd_, SOMAXCONN) == LISTEN_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("listen:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Socket::set_fd_to_nonblock() const {
	errno = 0;
	if (fcntl(this->socket_fd_, F_SETFL, O_NONBLOCK | FD_CLOEXEC) == FCNTL_ERROR) {
		std::string err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err("fcntl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}

int Socket::get_socket_fd() const { return this->socket_fd_; }
Result<int, std::string> Socket::get_socket_result() const { return this->result_; }
bool Socket::is_socket_success() const { return this->result_.is_ok(); }
