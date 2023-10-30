#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Server.hpp"

namespace {

Result<int, std::string> accept_connection(int socket_fd) {
	int connect_fd;

	errno = 0;
	connect_fd = accept(socket_fd, NULL, NULL);  // NULL:peer addr not needed
	if (connect_fd == ACCEPT_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(connect_fd);
}

Result<std::string, std::string> recv_request(int connect_fd) {
	char		buf[BUFSIZ + 1];
	ssize_t		recv_size;
	std::string	recv_msg;

	while (true) {
		errno = 0;
		recv_size = recv(connect_fd, buf, BUFSIZ, FLAG_NONE);
		// todo: flg=MSG_DONTWAIT, errno=EAGAIN -> continue?
		if (recv_size == RECV_ERROR || recv_size > BUFSIZ) {
			return Result<std::string, std::string>::err(strerror(errno));
		}
		buf[recv_size] = '\0';
		recv_msg += buf;
		if (recv_size < BUFSIZ) {
			break;
		}
	}
	return Result<std::string, std::string>::ok(recv_msg);
}

Result<int, std::string> send_response(int connect_fd, const HttpResponse &response) {
	char	*response_message = response.get_response_message();
	size_t	message_len = response.get_response_size();

	errno = 0;
	if (send(connect_fd, response_message, message_len, MSG_DONTWAIT) == SEND_ERROR) {
		return Result<int, std::string>::err(strerror(errno));
	}
	return Result<int, std::string>::ok(OK);
}

void stop_by_signal(int sig) {
	DEBUG_SERVER_PRINT("stop by signal %d", sig);
	std::cerr << "[Server] Stop running by signal" << std::endl;
	std::exit(0);
}

Result<int, std::string> set_signal() {
	std::string err_info;

	errno = 0;
	if (signal(SIGABRT, stop_by_signal) == SIG_ERR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err(err_info);
	}
	if (signal(SIGINT, stop_by_signal) == SIG_ERR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err(err_info);
	}
	if (signal(SIGTERM, stop_by_signal) == SIG_ERR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err(err_info);
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err(err_info);
	}
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		err_info = create_error_info(errno, __FILE__, __LINE__);
		return Result<int, std::string>::err(err_info);
	}
	return Result<int, std::string>::ok(OK);
}

Result<IOMultiplexer *, std::string> create_io_multiplexer_fds(int socket_fd) {
	IOMultiplexer *fds;

	try {
#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)
		fds = new EPollMultiplexer(socket_fd);
#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)
		fds = new KqueueMultiplexer(socket_fd);
#else
		fds = new SelectMultiplexer(socket_fd);
#endif
	} catch (std::bad_alloc const &e) {
		std::string err_info = create_error_info("Failed to allocate memory", __FILE__, __LINE__);
		return Result<IOMultiplexer *, std::string>::err(err_info);
	}
	return Result<IOMultiplexer *, std::string>::ok(fds);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

Server::Server(const Config &config)
	: _socket(config),
	  _recv_message(),
	  _fds(NULL) {
	Result<int, std::string> socket_result, signal_result;
	Result<IOMultiplexer *, std::string> fds_result;

	socket_result = this->_socket.get_socket_result();
	if (socket_result.is_err()) {
		std::string socket_err_msg = socket_result.get_err_value();
		throw std::runtime_error(RED "[Server Error] Initialization error: " + socket_err_msg + RESET);
	}

	signal_result = set_signal();
	if (signal_result.is_err()) {
		throw std::runtime_error(RED "[Server Error] Initialization error: signal: " + signal_result.get_err_value() + RESET);
	}

	fds_result = create_io_multiplexer_fds(this->_socket.get_socket_fd());
	if (fds_result.is_err()) {
		throw std::runtime_error(RED "[Server Error] Initialization error: " + fds_result.get_err_value() + RESET);
	}
	this->_fds = fds_result.get_ok_value();
}

Server::~Server() { delete this->_fds; }

////////////////////////////////////////////////////////////////////////////////

void Server::process_client_connection() {
	Result<int, std::string> fd_ready_result;
	int ready_fd;

	while (true) {
		fd_ready_result = this->_fds->get_io_ready_fd();
		if (fd_ready_result.is_err()) {
			throw std::runtime_error(RED + fd_ready_result.get_err_value() + RESET);
		}
		if (fd_ready_result.get_ok_value() == IO_TIMEOUT) {
			std::cerr << "[Server INFO] timeout" << std::endl;
			break;
		}

		ready_fd = fd_ready_result.get_ok_value();
		fd_ready_result = communicate_with_client(ready_fd);
		if (fd_ready_result.is_err()) {
			throw std::runtime_error(RED + fd_ready_result.get_err_value() + RESET);
		}
	}
}

Result<int, std::string> Server::communicate_with_client(int ready_fd) {
	if (ready_fd == this->_socket.get_socket_fd()) {
		return accept_and_store_connect_fd();
	} else {
		return communicate_with_ready_client(ready_fd);
	}
}

Result<int, std::string> Server::accept_and_store_connect_fd() {
	int connect_fd;
	std::string err_info;
	Result<int, std::string> accept_result, fd_store_result;

	accept_result = accept_connection(this->_socket.get_socket_fd());
	if (accept_result.is_err()) {
		err_info = create_error_info(accept_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] accept: " + err_info);
	}
	connect_fd = accept_result.get_ok_value();

	fd_store_result = this->_fds->register_connect_fd(connect_fd);
	if (fd_store_result.is_err()) {
		err_info = create_error_info(fd_store_result.get_err_value(), __FILE__, __LINE__);
		std::cerr << "[Server Error]" << err_info << std::endl;
		errno = 0;
		if (close(connect_fd) == CLOSE_ERROR) {
			err_info = create_error_info(errno, __FILE__, __LINE__);
			std::cerr << "[Server Error] close: "<< err_info << std::endl;
		}
	}
	return Result<int, std::string>::ok(OK);
}

Result<int, std::string> Server::communicate_with_ready_client(int ready_fd) {
	Result<std::string, std::string>recv_result;
	Result<int, std::string> send_result, clear_result;
	std::string err_info;

	recv_result = recv_request(ready_fd);
	if (recv_result.is_err()) {
		err_info = create_error_info(recv_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] recv: " + err_info);
	}
	this->_recv_message = recv_result.get_ok_value();
	DEBUG_SERVER_PRINT("connected. recv:[%s]", this->_recv_message.c_str());

	// request, response
	HttpRequest request(this->_recv_message);
	HttpResponse response = HttpResponse(request);

	// send
	send_result = send_response(ready_fd, response);
	if (send_result.is_err()) {
		// printf(BLUE "   server send error\n" RESET);
		err_info = create_error_info(send_result.get_err_value(), __FILE__, __LINE__);
		return Result<int, std::string>::err("[Server Error] send: " + err_info);
	}

	clear_result = this->_fds->clear_fd(ready_fd);
	if (clear_result.is_err()) {
		err_info = create_error_info(clear_result.get_err_value(), __FILE__, __LINE__);
		std::cerr << "[Server Error] clear_fd: " + err_info << std::endl;
	}
	return Result<int, std::string>::ok(OK);
}

std::string Server::get_recv_message() const { return this->_recv_message; }  // todo: for test, debug
