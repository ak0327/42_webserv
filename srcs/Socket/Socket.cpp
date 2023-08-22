#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "webserv.hpp"
#include "Socket.hpp"

Socket::Socket() : _status(ERROR),
				   _socket_fd(ERROR),
				   _addr_info(NULL),
				   _server_ip(SERVER_IP),
				   _server_port(SERVER_PORT) {
	if (create_socket() == ERROR) {
		return;
	}
	if (bind_socket() == ERROR) {
		return;
	}
	if (listen_socket() == ERROR) {
		return;
	}
	if (set_fd_to_nonblock() == ERROR) {
		return;
	}
	this->_status = OK;
}

Socket::~Socket() {
	if (this->_addr_info != NULL) {
		freeaddrinfo(this->_addr_info);
	}
	if (this->_socket_fd != ERROR) {
		close_socket_fd(this->_socket_fd);
	}
}

int Socket::create_socket() {
	int errcode;
	int ai_family, ai_socktype, ai_protocol;

	errcode = set_addr_info(&this->_addr_info);
	if (errcode != OK) {
		std::cerr << gai_strerror(errcode) << std::endl;
		return ERROR;
	}

	ai_family = this->_addr_info->ai_family;
	ai_socktype = this->_addr_info->ai_socktype;
	ai_protocol = this->_addr_info->ai_protocol;
	errno = 0;
	this->_socket_fd = socket(ai_family, ai_socktype, ai_protocol);
	if (this->_socket_fd == ERROR) {
		std::cerr << strerror(errno) << std::endl;
		return ERROR;
	}
	return OK;
}

/*
 listen 192.168.1.2:80;
 listen 80;
 */
int Socket::set_addr_info(const char *ip, const char *port, struct addrinfo **result) {
	struct addrinfo	hints = {};
	int				errcode;

	set_addr_hints(&hints);
	errcode = getaddrinfo(ip, port, &hints, result);
	return errcode;
}

void Socket::set_addr_hints(struct addrinfo *hints) {
	memset(hints, 0, sizeof(struct addrinfo));
	hints->ai_socktype = SOCK_STREAM;
	hints->ai_family = AF_UNSPEC;  // allows IPv4 and IPv6
	hints->ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;  // socket, IP, PORT
	hints->ai_protocol = IPPROTO_TCP;
}

int Socket::bind_socket() const {
	const struct sockaddr	*ai_addr;
	socklen_t				ai_addrlen;

	if (set_socket_opt(this->_socket_fd) == ERROR) {
		return ERROR;
	}
	ai_addr = this->_addr_info->ai_addr;
	ai_addrlen = this->_addr_info->ai_addrlen;
	errno = 0;
	if (bind(this->_socket_fd, ai_addr, ai_addrlen) == ERROR) {
		std::cerr << strerror(errno) << std::endl;
		return ERROR;
	}
	return OK;
}

int Socket::set_socket_opt(int socket_fd) {
	int			opt_val = 1;
	socklen_t	opt_len = sizeof(opt_val);

	errno = 0;
	if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt_val, opt_len) == ERROR) {
		std::cout << strerror(errno) << std::endl;
		return ERROR;
	}
	return OK;
}

int Socket::listen_socket() const {
	errno = 0;
	if (listen(this->_socket_fd, SOMAXCONN) == ERROR) {
		std::cerr << strerror(errno) << std::endl;
		return ERROR;
	}
	return OK;
}

int Socket::set_fd_to_nonblock() const {
	errno = 0;
	if (fcntl(this->_socket_fd, F_SETFL, O_NONBLOCK | FD_CLOEXEC) == ERROR) {
		std::cerr << strerror(errno) << std::endl;
		return ERROR;
	}
	return OK;
}

void Socket::close_socket_fd(int socket_fd) {
	errno = 0;
	if (close(socket_fd) == ERROR) {
		std::cerr << strerror(errno) << std::endl;
	}
}

int Socket::get_socket_fd() const { return this->_socket_fd; }
int Socket::get_status() const { return this->_status; }
