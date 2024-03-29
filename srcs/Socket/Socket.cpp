#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>
#include "Color.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


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


Result<int, std::string> Socket::create_socket() {
    SocketResult init_result = Socket::init();
    if (init_result.is_err()) {
        return Result<int, std::string>::err(init_result.err_value());
    }

    SocketResult bind_result = Socket::bind();
    if (bind_result.is_err()) {
        return Result<int, std::string>::err(bind_result.err_value());
    }

    SocketResult listen_result = Socket::listen();
    if (listen_result.is_err()) {
        return Result<int, std::string>::err(listen_result.err_value());
    }

    SocketResult set_fd_result = Socket::set_fd_to_nonblock();
    if (set_fd_result.is_err()) {
        return Result<int, std::string>::err(set_fd_result.err_value());
    }
    return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Socket::init() {
    SocketResult result = init_addr_info();
    if (result.is_err()) {
        return Result<int, std::string>::err(result.err_value());
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


SocketResult Socket::set_fd_to_keepalive(int fd) {
    const int val = 1;
    const socklen_t	opt_len = sizeof(val);

    errno = 0;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, opt_len) == SETSOCKOPT_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("setsocketopt: " + err_info);
    }
    return Result<int, std::string>::ok(OK);
}


AddressPortPair Socket::get_server_listen() {
    return std::make_pair(this->server_ip_, this->server_port_);
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


Result<std::size_t, ErrMsg> Socket::recv(int fd, void *buf, std::size_t bufsize) {
    errno = 0;
    ssize_t recv_size = ::recv(fd, buf, bufsize, FLAG_NONE);
    if (recv_size == RECV_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<std::size_t, ErrMsg>::err(error_msg);
    }
    return Result<std::size_t, ErrMsg>::ok(static_cast<std::size_t>(recv_size));
}


Result<ProcResult, ErrMsg> Socket::recv_to_buf(int fd, std::vector<unsigned char> *buf) {
    if (!buf) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("fatal error: null assigned to buf");
        return Result<ProcResult, ErrMsg>::err(error_msg);
    }
    // std::size_t bufsize = BUFSIZ;
    // std::size_t bufsize = 85;
    std::vector<unsigned char> recv_buf(BUFSIZ);

    DEBUG_SERVER_PRINT("recv start");
    Result<std::size_t, ErrMsg> recv_result = Socket::recv(fd, &recv_buf[0], BUFSIZ);
    if (recv_result.is_err()) {
        return Result<ProcResult, ErrMsg>::err(recv_result.err_value());
    }

    std::size_t recv_size = recv_result.ok_value();
    DEBUG_PRINT(RED, " recv_size: %zd", recv_size);
    if (0 < recv_size) {
        std::string debug_recv_msg(recv_buf.begin(), recv_buf.begin() + recv_size);
        DEBUG_SERVER_PRINT(" recv_msg[%s]", debug_recv_msg.c_str());

        buf->insert(buf->end(), recv_buf.begin(), recv_buf.begin() + recv_size);
    }
    DEBUG_SERVER_PRINT("recv end, bufsize:%zu", buf->size());
    return Result<ProcResult, ErrMsg>::ok(0 < recv_size ? Success : ConnectionClosed);
}


Result<std::size_t, ErrMsg> Socket::send(int fd, void *buf, std::size_t bufsize) {
    errno = 0;
    ssize_t send_size = ::send(fd, buf, bufsize, FLAG_NONE);
    if (send_size == SEND_ERROR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<std::size_t, ErrMsg>::err(error_msg);
    }
    return Result<std::size_t, ErrMsg>::ok(static_cast<std::size_t>(send_size));
}


Result<ProcResult, ErrMsg> Socket::send_buf(int fd, std::vector<unsigned char> *buf) {
    DEBUG_SERVER_PRINT("send start");
    if (!buf) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("fatal error: null assigned to buf");
        return Result<ProcResult, ErrMsg>::err(error_msg);
    }

    Result<std::size_t, ErrMsg> send_result = Socket::send(fd, buf->data(), buf->size());
    if (send_result.is_err()) {
        return Result<ProcResult, ErrMsg>::err(send_result.err_value());
    }
    std::size_t send_size = send_result.ok_value();
    DEBUG_SERVER_PRINT(" send size: %zd", send_size);
    if (0 < send_size) {
        DEBUG_SERVER_PRINT(" erase buf");
        buf->erase(buf->begin(), buf->begin() + send_size);
    }
    DEBUG_SERVER_PRINT("send end size: %zd", send_size);
    return Result<ProcResult, ErrMsg>::ok(buf->empty() ? Success : Continue);
}
