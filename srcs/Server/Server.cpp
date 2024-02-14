#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <iostream>
#include <set>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Configuration.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Server.hpp"

namespace {

const int MAX_SESSION = 128;

ServerResult accept_connection(int socket_fd) {
	int connect_fd;

	errno = 0;
	connect_fd = accept(socket_fd, NULL, NULL);  // NULL:peer addr not needed
	if (connect_fd == ACCEPT_ERROR) {
		return ServerResult::err(strerror(errno));
	}
	return ServerResult::ok(connect_fd);
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

ServerResult send_response(int connect_fd, const HttpResponse &response) {
	char	*response_message = response.get_response_message();
	size_t	message_len = response.get_response_size();

	errno = 0;
	if (send(connect_fd, response_message, message_len, MSG_DONTWAIT) == SEND_ERROR) {
		return ServerResult::err(strerror(errno));
	}
	return ServerResult::ok(OK);
}

void stop_by_signal(int sig) {
	DEBUG_SERVER_PRINT("stop by signal %d", sig);
	std::cerr << "[Server] Stop running by signal" << std::endl;
	std::exit(0);
}

ServerResult set_signal() {
	std::string err_info;

	errno = 0;
	if (signal(SIGABRT, stop_by_signal) == SIG_ERR) {
		err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(err_info);
	}
	if (signal(SIGINT, stop_by_signal) == SIG_ERR) {
		err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(err_info);
	}
	if (signal(SIGTERM, stop_by_signal) == SIG_ERR) {
		err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(err_info);
	}
	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(err_info);
	}
	if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
		err_info = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(err_info);
	}
	return ServerResult::ok(OK);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Server::Server(const Configuration &config)
	: sockets_(),
      recv_message_(),
      fds_(NULL) {
    ServerResult socket_result = create_sockets(config);
	if (socket_result.is_err()) {
		const std::string socket_err_msg = socket_result.get_err_value();
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << socket_err_msg << RESET;
		throw std::runtime_error(oss.str());
	}

    ServerResult signal_result = set_signal();
	if (signal_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: signal: " << signal_result.get_err_value() << RESET;
        throw std::runtime_error(oss.str());
	}

    Result<IOMultiplexer *, std::string> fds_result = create_io_multiplexer_fds();
	if (fds_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << fds_result.get_err_value() << RESET;
        throw std::runtime_error(oss.str());
	}
	this->fds_ = fds_result.get_ok_value();
}

Server::~Server() {
    delete this->fds_;
    delete_sockets();
    close_client_fds();
}

////////////////////////////////////////////////////////////////////////////////

ServerResult Server::create_sockets(const Configuration &config) {
    const std::map<ServerInfo, const ServerConfig *> &server_configs = config.get_server_configs();

    std::map<ServerInfo, const ServerConfig *>::const_iterator servers;
    for (servers = server_configs.begin(); servers != server_configs.end(); ++servers) {
        const std::string address = servers->first.address;
        const std::string port = servers->first.port;

        // std::cout << CYAN
        // << "create_sockets -> ip: " << address
        // << ", port: " << port << RESET << std::endl;

        try {
            Socket *socket = new Socket(address, port);
            if (socket->is_socket_success()) {
                int socket_fd = socket->get_socket_fd();
                sockets_[socket_fd] = socket;
                // std::cout << "socket_fd: " << socket_fd << std::endl;
                continue;
            }
            const std::string error_msg = socket->get_socket_result().get_err_value();
            delete socket;
            return ServerResult::err(error_msg);
        }
        catch (std::bad_alloc const &e) {
            std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
            return ServerResult ::err(err_info);
        }
    }
    return ServerResult::ok(OK);
}


void Server::delete_sockets() {
    std::map<Fd, Socket *>::iterator itr;
    for (itr = this->sockets_.begin(); itr != this->sockets_.end(); ++itr) {
        delete itr->second;
    }
    this->sockets_.clear();
}


void Server::close_client_fds() {
    std::deque<int>::iterator fd;
    for (fd = this->client_fds_.begin(); fd != this->client_fds_.end(); ++fd) {
        if (*fd == INIT_FD) {
            continue;
        }
        close(*fd);
    }
    this->client_fds_.clear();
}


Result<IOMultiplexer *, std::string> Server::create_io_multiplexer_fds() {
    try {
#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)
        IOMultiplexer *fds = new EPollMultiplexer();
#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)
        IOMultiplexer *fds = new KqueueMultiplexer();
#else
        IOMultiplexer *fds = new SelectMultiplexer();
#endif
        std::map<Fd, Socket *>::const_iterator socket;
        for (socket = this->sockets_.begin(); socket != this->sockets_.end(); ++socket) {
            int socket_fd = socket->first;

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)
            fds->register_fd(socket_fd);
#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)
            fds->register_fd(socket_fd);
#else
            fds->register_fd(socket_fd);
#endif
            this->socket_fds_.push_back(socket_fd);
        }
        return Result<IOMultiplexer *, std::string>::ok(fds);
    } catch (std::bad_alloc const &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<IOMultiplexer *, std::string>::err(err_info);
    }
}


////////////////////////////////////////////////////////////////////////////////


void Server::process_client_connection() {
	while (true) {
        ServerResult fd_ready_result = this->fds_->get_io_ready_fd();
		if (fd_ready_result.is_err()) {
			throw std::runtime_error(RED + fd_ready_result.get_err_value() + RESET);
		}
		if (fd_ready_result.get_ok_value() == IO_TIMEOUT) {
			std::cerr << "[Server INFO] timeout" << std::endl;
			break;
		}

		int ready_fd = fd_ready_result.get_ok_value();
		fd_ready_result = communicate_with_client(ready_fd);
		if (fd_ready_result.is_err()) {
			throw std::runtime_error(RED + fd_ready_result.get_err_value() + RESET);
		}
	}
}


bool Server::is_socket_fd(int fd) const {
    return this->sockets_.find(fd) != this->sockets_.end();
}


ServerResult Server::communicate_with_client(int ready_fd) {
	if (is_socket_fd(ready_fd)) {
		return accept_connect_fd(ready_fd);
	} else {
		return communicate_with_ready_client(ready_fd);
	}
}


ServerResult Server::accept_connect_fd(int socket_fd) {
    if (MAX_SESSION <= this->client_fds_.size()) {
        std::cerr << "[Server Error] exceed max connection" << std::endl;
        return ServerResult::ok(OK);  // todo: continue, ok?
    }

    ServerResult accept_result = accept_connection(socket_fd);
	if (accept_result.is_err()) {
		const std::string err_info = CREATE_ERROR_INFO_STR(accept_result.get_err_value());
		return ServerResult::err("[Server Error] accept: " + err_info);
	}
	int connect_fd = accept_result.get_ok_value();
    this->client_fds_.push_back(connect_fd);

    ServerResult fd_store_result = this->fds_->register_fd(connect_fd);
	if (fd_store_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(fd_store_result.get_err_value());
		std::cerr << "[Server Error]" << err_info << std::endl;
		errno = 0;
		if (close(connect_fd) == CLOSE_ERROR) {
			err_info = CREATE_ERROR_INFO_ERRNO(errno);
			std::cerr << "[Server Error] close: "<< err_info << std::endl;
		}
	}
	return ServerResult::ok(OK);
}


ServerResult Server::communicate_with_ready_client(int connect_fd) {
    Result<std::string, std::string> recv_result = recv_request(connect_fd);
	if (recv_result.is_err()) {
		const std::string err_info = CREATE_ERROR_INFO_STR(recv_result.get_err_value());
		return ServerResult::err("[Server Error] recv: " + err_info);
	}
	this->recv_message_ = recv_result.get_ok_value();
	DEBUG_SERVER_PRINT("connected. recv:[%s]", this->recv_message_.c_str());

	// request, response
	HttpRequest request(this->recv_message_);
	HttpResponse response = HttpResponse(request);

	// send
    ServerResult send_result = send_response(connect_fd, response);
	if (send_result.is_err()) {
		// printf(BLUE "   server send error\n" RESET);
		const std::string err_info = CREATE_ERROR_INFO_STR(send_result.get_err_value());
		return ServerResult::err("[Server Error] send: " + err_info);
	}

    ServerResult clear_result = this->fds_->clear_fd(connect_fd);
	if (clear_result.is_err()) {
		const std::string err_info = CREATE_ERROR_INFO_STR(clear_result.get_err_value());
		std::cerr << "[Server Error] clear_fd: " + err_info << std::endl;
	}
	return ServerResult::ok(OK);
}


std::string Server::get_recv_message() const { return this->recv_message_; }  // todo: for test, debug
