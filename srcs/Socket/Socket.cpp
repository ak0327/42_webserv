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


////////////////////////////////////////////////////////////////////////////////


Socket::Socket(const std::string &ip_addr, const std::string &port)
    : socket_fd_(INIT_FD),
      addr_info_(NULL),
      server_ip_(ip_addr),
      server_port_(port) {}


Socket::~Socket() {
    if (this->addr_info_ != NULL) {
		freeaddrinfo(this->addr_info_);
		this->addr_info_ = NULL;
	}
	if (this->socket_fd_ != INIT_FD) {
        errno = 0;
        if (close(this->socket_fd_) == CLOSE_ERROR) {
            std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
            std::cerr << "close:" << err_info << std::endl;
        }
		this->socket_fd_ = INIT_FD;
	}
}


Result<int, std::string> Socket::init_addr_info() {
	struct addrinfo	hints = {};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;  // IPv4  AF_UNSPEC; allows IPv4 and IPv6
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;  // socket, IP, PORT
    hints.ai_protocol = IPPROTO_TCP;
    const char *ip = (this->server_ip_ != "*") ? this->server_ip_.c_str() : NULL;
	struct addrinfo	*ret_addr_info;
	int errcode = getaddrinfo(ip, this->server_port_.c_str(), &hints, &ret_addr_info);

	if (errcode != GETADDRINFO_SUCCESS) {
		std::string err_info = CREATE_ERROR_INFO_STR(gai_strerror(errcode));
		return Result<int, std::string>::err("getaddrinfo:" + err_info);
	}
	this->addr_info_ = ret_addr_info;
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::init() {
    SocketResult result = init_addr_info();
    if (result.is_err()) {
        return Result<int, std::string>::err(result.get_err_value());
    }
	const int ai_family = this->addr_info_->ai_family;
	const int ai_socktype = this->addr_info_->ai_socktype;
	const int ai_protocol = this->addr_info_->ai_protocol;

	errno = 0;
	int socket_fd = socket(ai_family, ai_socktype, ai_protocol);
	if (socket_fd == SOCKET_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("socket:" + err_info);
	}
	this->socket_fd_ = socket_fd;
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::bind() {
    const int opt_val = 1;
    const socklen_t	opt_len = sizeof(opt_val);
    errno = 0;
    if (setsockopt(this->socket_fd_, SOL_SOCKET, SO_REUSEADDR, &opt_val, opt_len) == SETSOCKOPT_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("setsocketopt: " + err_info);
    }

	const struct sockaddr *ai_addr = this->addr_info_->ai_addr;
	const socklen_t ai_addrlen = this->addr_info_->ai_addrlen;
	errno = 0;
	if (::bind(this->socket_fd_, ai_addr, ai_addrlen) == BIND_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("bind:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::listen() {
	errno = 0;
	if (::listen(this->socket_fd_, SOMAXCONN) == LISTEN_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("listen:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::connect() {
    errno = 0;
    if (::connect(this->socket_fd_, this->addr_info_->ai_addr, this->addr_info_->ai_addrlen) == CONN_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("connect:" + err_info);
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::accept(int socket_fd,
                                        struct sockaddr_storage *client_addr) {
    socklen_t client_addr_len = sizeof(struct sockaddr_storage);

    errno = 0;
    int connect_fd = ::accept(socket_fd, (struct sockaddr *)client_addr, &client_addr_len);
    if (connect_fd == ACCEPT_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("accept:" + err_info);
    }
    return Result<int, std::string>::ok(connect_fd);
}


SocketResult Socket::set_fd_to_nonblock() {
    return set_fd_to_nonblock(this->socket_fd_);
}


Result<int, std::string> Socket::set_fd_to_nonblock(int fd) {
	errno = 0;
	if (fcntl(fd, F_SETFL, O_NONBLOCK) == FCNTL_ERROR) {
		std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return Result<int, std::string>::err("fcntl:" + err_info);
	}
	return Result<int, std::string>::ok(OK);
}


int Socket::get_socket_fd() const { return this->socket_fd_; }
