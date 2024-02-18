#include <errno.h>
#include <fcntl.h>
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
      fds_(NULL),
      config_(config) {}


Server::~Server() {
    std::map<Fd, ClientSession *>::iterator itr;
    for (itr = this->sessions_.begin(); itr != sessions_.end(); ++itr) {
        delete itr->second;
    }
    this->sessions_.clear();
    delete_sockets();
    delete this->fds_;
}

////////////////////////////////////////////////////////////////////////////////

ServerResult Server::init() {
    ServerResult socket_result = create_sockets(this->config_);
    if (socket_result.is_err()) {
        const std::string socket_err_msg = socket_result.get_err_value();
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << socket_err_msg << RESET;
        return ServerResult::err(oss.str());
    }

    ServerResult signal_result = set_signal();
    if (signal_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: signal: " << signal_result.get_err_value() << RESET;
        return ServerResult::err(oss.str());
    }

    Result<IOMultiplexer *, std::string> fds_result = create_io_multiplexer_fds();
    if (fds_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << fds_result.get_err_value() << RESET;
        return ServerResult::err(oss.str());
    }
    this->fds_ = fds_result.get_ok_value();
    return ServerResult::ok(OK);
}


Result<Socket *, std::string> Server::create_socket(const std::string &address,
                                                    const std::string &port) {
    Socket *socket = NULL;

    try {
        socket = new Socket(address, port);

        SocketResult init_result = socket->init();
        if (init_result.is_err()) {
            throw std::runtime_error(init_result.get_err_value());
        }

        SocketResult bind_result = socket->bind();
        if (bind_result.is_err()) {
            throw std::runtime_error(bind_result.get_err_value());
        }

        SocketResult listen_result = socket->listen();
        if (listen_result.is_err()) {
            throw std::runtime_error(listen_result.get_err_value());
        }

        SocketResult set_fd_result = socket->set_fd_to_nonblock();
        if (set_fd_result.is_err()) {
            throw std::runtime_error(set_fd_result.get_err_value());
        }

        return Result<Socket *, std::string>::ok(socket);
    }
    catch (std::bad_alloc const &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<Socket *, std::string>::err(err_info);
    }
    catch (std::runtime_error const &e) {
        delete socket;
        return Result<Socket *, std::string>::err(e.what());
    }
}


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
            Result<Socket *, std::string> socket_result = create_socket(address, port);
            if (socket_result.is_err()) {
                const std::string error_msg = socket_result.get_err_value();
                return ServerResult::err(error_msg);
            }
            Socket *socket = socket_result.get_ok_value();
            int socket_fd = socket->get_socket_fd();
            sockets_[socket_fd] = socket;
            // std::cout << "socket_fd: " << socket_fd << std::endl;
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


void Server::close_client_fd(int fd) {
    if (fd == INIT_FD) {
        return;
    }
    if (this->fds_) {
        this->fds_->clear_fd(fd);
    }
    std::deque<Fd>::iterator itr;
    for (itr = this->client_fds_.begin(); itr != this->client_fds_.end(); ++itr) {
        if (*itr != fd) {
            continue;
        }
        this->client_fds_.erase(itr);
        break;
    }
    int close_ret = close(fd);
    if (close_ret == CLOSE_ERROR) {
        std::cout << CYAN << "close error" << RESET << std::endl;  // todo: log
    }
}


Result<IOMultiplexer *, std::string> Server::create_io_multiplexer_fds() {
    try {
#if defined(__linux__) && !defined(USE_SELECT)
        IOMultiplexer *fds = new EPoll();
#elif defined(__APPLE__) && !defined(USE_SELECT)
        IOMultiplexer *fds = new Kqueue();
#else
        IOMultiplexer *fds = new Select();
#endif
        std::map<Fd, Socket *>::const_iterator socket;
        for (socket = this->sockets_.begin(); socket != this->sockets_.end(); ++socket) {
            int socket_fd = socket->first;

#if defined(__linux__) && !defined(USE_SELECT)
            fds->register_fd(socket_fd);
#elif defined(__APPLE__) && !defined(USE_SELECT)
            fds->register_fd(socket_fd);
#else
            fds->register_read_fd(socket_fd);
#endif
            this->socket_fds_.push_back(socket_fd);
            DEBUG_SERVER_PRINT(" socket_fd: %d", socket_fd);
        }
        return Result<IOMultiplexer *, std::string>::ok(fds);
    } catch (std::bad_alloc const &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<IOMultiplexer *, std::string>::err(err_info);
    }
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::run() {
	while (true) {
        DEBUG_SERVER_PRINT(" loop 1 get_io_ready_fd");
        ServerResult fd_ready_result = this->fds_->get_io_ready_fd();
        DEBUG_SERVER_PRINT(" loop 2 ready result");
		if (fd_ready_result.is_err()) {
            DEBUG_SERVER_PRINT(" loop : error 1");
            const std::string error_msg = fd_ready_result.get_err_value();
            return ServerResult::err(error_msg);
		}
		int ready_fd = fd_ready_result.get_ok_value();
        DEBUG_SERVER_PRINT("loop 3: ready_fd: %d", ready_fd);
		if (ready_fd == IO_TIMEOUT) {
			std::cerr << "[Server INFO] timeout" << std::endl;
			break;
		}
        DEBUG_SERVER_PRINT(" loop 4 communicate");
        ServerResult communicate_result = communicate_with_client(ready_fd);
		if (communicate_result.is_err()) {
            const std::string error_msg = communicate_result.get_err_value();
            DEBUG_SERVER_PRINT("");
            std::cout << GREEN << " loop : error 2" << RESET << std::endl;
            return ServerResult::err(error_msg);
		}
        DEBUG_SERVER_PRINT(" loop 5 next loop");
    }
    return ServerResult::ok(OK);
}


bool Server::is_socket_fd(int fd) const {
    return this->sockets_.find(fd) != this->sockets_.end();
}


ServerResult Server::create_session(int socket_fd) {
    struct sockaddr_storage client_addr = {};
    ServerResult accept_result = accept_connect_fd(socket_fd, &client_addr);
    if (accept_result.is_err()) {
        const std::string error_msg = accept_result.get_err_value();
        return ServerResult::err(error_msg);
    }
    int connect_fd = accept_result.get_ok_value();
    // todo: mv
    errno = 0;
    if (fcntl(connect_fd, F_SETFL, O_NONBLOCK | FD_CLOEXEC) == FCNTL_ERROR) {
        std::string err_info = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<int, std::string>::err("fcntl:" + err_info);
    }

    // std::cout << CYAN << " accept fd: " << connect_fd << RESET << std::endl;

    if (this->sessions_.find(connect_fd) != this->sessions_.end()) {
        return ServerResult::err("error: fd duplicated");  // ?
    }
    try {
        // std::cout << CYAN << " new_session created" << RESET << std::endl;
        AddressPortPair client_listen = ClientSession::get_client_listen(client_addr);

        std::ostringstream oss; oss << client_listen;
        DEBUG_SERVER_PRINT("%s", oss.str().c_str());

        ClientSession *new_session = new ClientSession(socket_fd, connect_fd, client_listen, this->config_);
        this->sessions_[connect_fd] = new_session;
        // std::cout << CYAN << " session start" << connect_fd << RESET << std::endl;
        return ServerResult::ok(OK);
    }
    catch (const std::exception &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory: " + std::string(e.what()));
        return ServerResult::err(err_info);
    }
}


void Server::update_fd_type_read_to_write(const SessionState &session_state, int fd) {
    FdType fd_type = this->fds_->get_fd_type(fd);
    if (session_state == kSendingResponse && fd_type == kReadFd) {
        this->fds_->clear_fd(fd);
        this->fds_->register_write_fd(fd);
        // std::cout << RED << "update write fd: " << fd << RESET << std::endl;
    }
}


void Server::delete_session(std::map<Fd, ClientSession *>::iterator session) {
    ClientSession *client_session = session->second;
    int client_fd = client_session->get_client_fd();

    this->fds_->clear_fd(client_fd);
    delete client_session;
    this->sessions_.erase(session);
}


bool is_cgi_fd(int result_value) {
    return result_value != OK;  // result_value is cgi_fd
}


ServerResult Server::process_session(int ready_fd) {
    std::map<Fd, ClientSession *>::iterator session = this->sessions_.find(ready_fd);
    if (session == this->sessions_.end()) {
        return ServerResult::err("error: fd unknown");
    }

    SessionResult result;
    ClientSession *client_session = session->second;
    if (ready_fd == client_session->get_client_fd()) {
        // std::cout << WHITE << " process_client_event" << RESET << std::endl;
        result = client_session->process_client_event();
    } else if (ready_fd == client_session->get_file_fd()) {
        // std::cout << WHITE << " process_file_event" << RESET << std::endl;
        result = client_session->process_file_event();
    } else {
        return ServerResult::err("error: fd unknown");
    }

    if (result.is_err()) {
        const std::string error_msg = result.get_err_value();
        return ServerResult::err(error_msg);
    }
    int result_value = result.get_ok_value();
    if (is_cgi_fd(result_value)) {
        int cgi_fd = result_value;
        this->fds_->register_read_fd(cgi_fd);
        return ServerResult::ok(OK);
    }
    update_fd_type_read_to_write(client_session->get_session_state(), ready_fd);

    if (client_session->is_session_completed()) {
        // std::cout << WHITE << " session complete fd: " << ready_fd << RESET << std::endl;
        delete_session(session);
    }
    return ServerResult::ok(OK);
}


ServerResult Server::communicate_with_client(int ready_fd) {
	if (is_socket_fd(ready_fd)) {
        DEBUG_SERVER_PRINT("  ready_fd=socket fd: %d", ready_fd);
        return create_session(ready_fd);
	} else {
        DEBUG_SERVER_PRINT("  ready_fd=client fd: %d", ready_fd);
        return process_session(ready_fd);
    }
}


ServerResult Server::accept_connect_fd(int socket_fd,
                                       struct sockaddr_storage *client_addr) {
    if (MAX_SESSION <= this->client_fds_.size()) {
        std::cerr << "[Server Error] exceed max connection" << std::endl;
        return ServerResult::ok(OK);  // todo: continue, ok?
    }

    SocketResult accept_result = Socket::accept(socket_fd, client_addr);
    if (accept_result.is_err()) {
        const std::string error_msg = accept_result.get_err_value();
        return ServerResult::err(error_msg);
    }
	int connect_fd = accept_result.get_ok_value();
    DEBUG_SERVER_PRINT("  accepted connect fd: %d", connect_fd);

    ServerResult fd_register_result = this->fds_->register_read_fd(connect_fd);
	if (fd_register_result.is_err()) {
		std::string err_info = CREATE_ERROR_INFO_STR(fd_register_result.get_err_value());
		std::cerr << "[Server Error]" << err_info << std::endl;
		errno = 0;
		if (close(connect_fd) == CLOSE_ERROR) {
			err_info = CREATE_ERROR_INFO_ERRNO(errno);
			std::cerr << "[Server Error] close: "<< err_info << std::endl;
		}
	}
    this->client_fds_.push_back(connect_fd);
	return ServerResult::ok(connect_fd);
}


void Server::set_timeout(int timeout_msec) {
    this->fds_->set_timeout(timeout_msec);
}
