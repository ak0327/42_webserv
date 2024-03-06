#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <iostream>
#include <set>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Config.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "IOMultiplexer.hpp"
#include "Result.hpp"
#include "Server.hpp"

namespace {

void detect_received_signal(int sig) {
    switch (sig) {
        case SIGINT:
            std::cout << RED << "Received SIGINT" << RESET << std::endl;
            // std::cout << "[Server] Running stop" << std::endl;
            std::exit(EXIT_SUCCESS);

        case SIGTERM:
            std::cout << RED << "Received SIGTERM" << RESET << std::endl;
            // std::cout << "[Server] Running stop by SIGTERM" << std::endl;
            std::exit(EXIT_SUCCESS);

        case SIGABRT:
            std::cout << RED << "Received SIGABORT" << RESET << std::endl;
            // std::cout << "[Error] Server abort" << std::endl;
            std::exit(EXIT_FAILURE);

        case SIGPIPE:
            std::cout << RED << "Received SIGPIPE" << RESET << std::endl;
            break;
            std::exit(EXIT_FAILURE);

        default:
            std::cout << "Received unknown signal: " << sig << std::endl;
    }
}


ServerResult set_signal() {
    // return ServerResult::ok(OK);

	errno = 0;
	if (signal(SIGABRT, detect_received_signal) == SIG_ERR) {
		const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(error_msg);
	}
	if (signal(SIGINT, detect_received_signal) == SIG_ERR) {
		const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(error_msg);
	}
	if (signal(SIGTERM, detect_received_signal) == SIG_ERR) {
		const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(error_msg);
	}
    if (signal(SIGPIPE, detect_received_signal) == SIG_ERR) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        return ServerResult::err(error_msg);
    }
	return ServerResult::ok(OK);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Server::Server(const Config &config)
	: sockets_(),
      fds_(NULL),
      config_(config),
      echo_mode_on_(false) {
    DEBUG_PRINT(WHITE, "timeout:");
    DEBUG_PRINT(WHITE, " recv      : %zu", config.recv_timeout());
    DEBUG_PRINT(WHITE, " send      : %zu", config.send_timeout());
    DEBUG_PRINT(WHITE, " keep-alive: %zu", config.keepalive_timeout());
}


Server::~Server() {
    clear_event();
    delete_sockets();
    delete this->fds_;
}

////////////////////////////////////////////////////////////////////////////////

ServerResult Server::init() {
    ServerResult socket_result = create_sockets(this->config_);
    if (socket_result.is_err()) {
        const std::string socket_err_msg = socket_result.err_value();
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << socket_err_msg << RESET;
        return ServerResult::err(oss.str());
    }

    ServerResult signal_result = set_signal();
    if (signal_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: signal: " << signal_result.err_value() << RESET;
        return ServerResult::err(oss.str());
    }

    Result<IOMultiplexer *, std::string> fds_result = create_io_multiplexer_fds();
    if (fds_result.is_err()) {
        std::ostringstream oss;
        oss << RED << "[Server Error] Initialization error: " << fds_result.err_value() << RESET;
        return ServerResult::err(oss.str());
    }
    this->fds_ = fds_result.ok_value();
    return ServerResult::ok(OK);
}


Result<Socket *, std::string> Server::create_socket(const std::string &address,
                                                    const std::string &port) {
    Socket *socket = NULL;

    try {
        socket = new Socket(address, port);

        SocketResult init_result = socket->init();
        if (init_result.is_err()) {
            throw std::runtime_error(init_result.err_value());
        }

        SocketResult bind_result = socket->bind();
        if (bind_result.is_err()) {
            throw std::runtime_error(bind_result.err_value());
        }

        SocketResult listen_result = socket->listen();
        if (listen_result.is_err()) {
            throw std::runtime_error(listen_result.err_value());
        }

        SocketResult set_fd_result = socket->set_fd_to_nonblock();
        if (set_fd_result.is_err()) {
            throw std::runtime_error(set_fd_result.err_value());
        }

        return Result<Socket *, std::string>::ok(socket);
    }
    catch (std::bad_alloc const &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<Socket *, std::string>::err(err_info);
    }
    catch (std::runtime_error const &e) {
        delete socket;
        const std::string error_msg = CREATE_ERROR_INFO_STR(e.what());
        return Result<Socket *, std::string>::err(error_msg);
    }
}


ServerResult Server::create_sockets(const Config &config) {
    // const std::map<ServerInfo, const ServerConfig *> &server_configs = config.get_server_configs();
    // DEBUG_PRINT(GRAY_BACK, "conf server:");
    // std::map<ServerInfo, const ServerConfig *>::const_iterator itr;
    // for (itr = server_configs.begin(); itr != server_configs.end(); ++itr) {
    //     ServerInfo s = itr->first;
    //     DEBUG_PRINT(GRAY_BACK, " name: %s, ip: %s, port: %s", s.server_name.c_str(), s.address.c_str(), s.port.c_str());
    // }
    const std::map<AddressPortPair, const ServerConfig *> &default_servers = config.get_default_servers();

    DEBUG_PRINT(GRAY_BACK, "create sockets:");
    std::map<AddressPortPair, const ServerConfig *>::const_iterator servers;
    for (servers = default_servers.begin(); servers != default_servers.end(); ++servers) {
        AddressPortPair server = servers->first;
        try {
            DEBUG_PRINT(GRAY_BACK, " ip: %s, port: %s", server.first.c_str(), server.second.c_str());
            Result<Socket *, std::string> socket_result = create_socket(server.first, server.second);
            if (socket_result.is_err()) {
                const std::string error_msg = socket_result.err_value();
                return ServerResult::err(error_msg);
            }
            Socket *socket = socket_result.ok_value();
            int socket_fd = socket->get_socket_fd();
            sockets_[socket_fd] = socket;
            // std::cout << "socket_fd: " << socket_fd << std::endl;
        }
        catch (const std::bad_alloc &e) {
            std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
            return ServerResult ::err(err_info);
        }
    }
    return ServerResult::ok(OK);
}


void Server::delete_sockets() {
    std::map<SocketFd , Socket *>::iterator itr;
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
    std::deque<ClientFd>::iterator itr;
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
#if defined(__linux__) && !defined(USE_SELECT) && !defined(USE_POLL)
        IOMultiplexer *fds = new EPoll();
#elif defined(__APPLE__) && !defined(USE_SELECT) && !defined(USE_POLL)
        IOMultiplexer *fds = new Kqueue();
#elif defined(USE_SELECT)
        IOMultiplexer *fds = new Select();
#else
        IOMultiplexer *fds = new Poll();
#endif
        std::map<SocketFd , Socket *>::const_iterator socket;
        for (socket = this->sockets_.begin(); socket != this->sockets_.end(); ++socket) {
            int socket_fd = socket->first;
            fds->register_read_fd(socket_fd);
            this->socket_fds_.push_back(socket_fd);
            DEBUG_SERVER_PRINT(" socket_fd: %d", socket_fd);
        }
        return Result<IOMultiplexer *, std::string>::ok(fds);
    } catch (const std::bad_alloc &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<IOMultiplexer *, std::string>::err(err_info);
    }
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::run() {
	while (true) {
        // char *p = new char[100]; (void)p;
        // sleep(1);
        DEBUG_SERVER_PRINT(" run 1 timeout management");
        management_timeout_events();
        set_io_timeout();

        DEBUG_SERVER_PRINT(" run 2 get_io_ready_fd");
        ServerResult fd_ready_result = this->fds_->get_io_ready_fd();
        DEBUG_SERVER_PRINT(" run 3 ready result");
		if (fd_ready_result.is_err()) {
            DEBUG_SERVER_PRINT(" run : error 1");
            const std::string error_msg = fd_ready_result.err_value();
            return ServerResult::err(error_msg);
		}
		int ready_fd = fd_ready_result.ok_value();
        DEBUG_SERVER_PRINT(" run 4 ready_fd: %d", ready_fd);
		if (ready_fd == IO_TIMEOUT) {
            if (this->echo_mode_on_) {
                DEBUG_SERVER_PRINT("  timeout -> break");
                break;
            } else {
                DEBUG_SERVER_PRINT("  timeout -> continue");
                continue;
            }
		}
        DEBUG_SERVER_PRINT(" run 5 communicate");

        ServerResult event_result = process_event(ready_fd);
		if (event_result.is_err()) {
            const std::string error_msg = event_result.err_value();
            DEBUG_SERVER_PRINT(" run : error 2");
            return ServerResult::err(error_msg);
		}
        DEBUG_SERVER_PRINT(" run 6 next loop");
    }
    return ServerResult::ok(OK);
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::echo() {
    this->echo_mode_on_ = true;
    return run();
}


void Server::update_fd_type_read_to_write(const EventPhase &event_state, int fd) {
    FdType fd_type = this->fds_->get_fd_type(fd);
    if (event_state == kSendingResponse && fd_type == kReadFd) {
        DEBUG_SERVER_PRINT("read_fd read -> write");
        this->fds_->clear_fd(fd);
        this->fds_->register_write_fd(fd);
        // std::cout << RED << "update write fd: " << fd << RESET << std::endl;
    }
}


void Server::delete_event(std::map<Fd, Event *>::iterator event) {
    Event *client_event = event->second;
    int client_fd = client_event->client_fd();

    this->fds_->clear_fd(client_fd);
    delete client_event;
    this->client_events_.erase(event);

    std::set<FdTimeoutLimitPair>::iterator itr;
    itr = find_fd_in_timeout_pair(client_fd, this->idling_client_time_manager_);
    if (itr != this->idling_client_time_manager_.end()) {
        this->idling_client_time_manager_.erase(itr);
    }

    itr = find_fd_in_timeout_pair(client_fd, this->active_client_time_manager_);
    if (itr != this->active_client_time_manager_.end()) {
        this->active_client_time_manager_.erase(itr);
    }
}


bool is_cgi_fd(int result_value) {
    return result_value != OK;  // result_value is cgi_fd
}


void Server::update_fd_type(int fd,
                            FdType update_from,
                            FdType update_to) {
    if (this->fds_->get_fd_type(fd) == update_to || update_from == update_to) {
        return;
    }
    this->fds_->clear_fd(fd);
    if (update_to == kReadFd) {
        this->fds_->register_read_fd(fd);
    } else if (update_to == kWriteFd) {
        this->fds_->register_write_fd(fd);
    }
}


void Server::clear_event() {
    std::map<ClientFd, Event *>::iterator event;
    for (event = this->client_events_.begin(); event != client_events_.end(); ++event) {
        delete event->second;
        event->second = NULL;
    }
    this->client_events_.clear();

    this->cgi_events_.clear();  // cgi_sessions_ has same pointer to client_sessions_
}


bool Server::is_fd_type_expect(int fd, const FdType &type) {
    return this->fds_->get_fd_type(fd) == type;
}


void Server::register_cgi_write_fd_to_event_manager(Event **client_event) {
    if (!client_event || !*client_event) { return; }

    int write_fd = (*client_event)->cgi_write_fd();
    DEBUG_SERVER_PRINT("       register cgi_fd to event_manager, cgi_write_fd: %d", write_fd);

    time_t timeout_limit = (*client_event)->cgi_timeout_limit();
    if (write_fd != INIT_FD) {
        this->fds_->register_write_fd(write_fd);
        this->cgi_events_[write_fd] = *client_event;
        DEBUG_SERVER_PRINT("        timeout: %zu, clilent: %p", timeout_limit, *client_event);
        this->cgi_fds_.insert(FdTimeoutLimitPair(timeout_limit, write_fd));
    }
}


void Server::register_cgi_read_fd_to_event_manager(Event **client_event) {
    if (!client_event || !*client_event) { return; }

    int read_fd = (*client_event)->cgi_read_fd();
    DEBUG_SERVER_PRINT("       register cgi_fd to event_manager, cgi_read_fd: %d", read_fd);

    time_t timeout_limit = (*client_event)->cgi_timeout_limit();
    if (read_fd != INIT_FD) {
        this->fds_->register_read_fd(read_fd);
        this->cgi_events_[read_fd] = *client_event;
        DEBUG_SERVER_PRINT("        timeout: %zu, clilent: %p", timeout_limit, *client_event);
        this->cgi_fds_.insert(FdTimeoutLimitPair(timeout_limit, read_fd));
    }
}


void Server::register_cgi_fds_to_event_manager(Event **client_event) {
    register_cgi_read_fd_to_event_manager(client_event);
    register_cgi_write_fd_to_event_manager(client_event);
}


void Server::clear_fd_from_event_manager(int fd) {
    if (fd == INIT_FD) {
        return;
    }
    this->cgi_events_.erase(fd);
    this->fds_->clear_fd(fd);
    erase_from_timeout_manager(fd);
}


void Server::clear_cgi_fds_from_event_manager(const Event &cgi_event) {
    clear_fd_from_event_manager(cgi_event.cgi_read_fd());
    clear_fd_from_event_manager(cgi_event.cgi_write_fd());
}
