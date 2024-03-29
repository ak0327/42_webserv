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
            std::cout << "server stop" << std::endl;
            // std::cout << RED << "Received SIGINT" << RESET << std::endl;
            // std::cout << "[Server] Running stop" << std::endl;
            std::exit(EXIT_SUCCESS);

        // case SIGTERM:
        //     std::cout << RED << "Received SIGTERM" << RESET << std::endl;
        //     // std::cout << "[Server] Running stop by SIGTERM" << std::endl;
        //     std::exit(EXIT_SUCCESS);
        //
        // case SIGABRT:
        //     std::cout << RED << "Received SIGABORT" << RESET << std::endl;
        //     // std::cout << "[Error] Server abort" << std::endl;
        //     std::exit(EXIT_FAILURE);

        // case SIGPIPE:
        //     std::cout << RED << "Received SIGPIPE" << RESET << std::endl;
            // std::exit(EXIT_FAILURE);
            // break;

        default:
            std::cout << "Received signal: " << sig << std::endl;
    }
}


ServerResult set_signal() {
	errno = 0;
	// if (signal(SIGABRT, detect_received_signal) == SIG_ERR) {
	// 	const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
	// 	return ServerResult::err(error_msg);
	// }
	if (signal(SIGINT, detect_received_signal) == SIG_ERR) {
		const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
		return ServerResult::err(error_msg);
	}
	// if (signal(SIGTERM, detect_received_signal) == SIG_ERR) {
	// 	const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
	// 	return ServerResult::err(error_msg);
	// }
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
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
    clear_events();
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
    }
    catch (std::bad_alloc const &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return Result<Socket *, std::string>::err(err_info);
    }

    SocketResult result = socket->create_socket();
    if (result.is_err()) {
        delete socket;
        return Result<Socket *, std::string>::err(result.err_value());
    }
    return Result<Socket *, std::string>::ok(socket);
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

    DEBUG_PRINT(BG_GRAY, "create sockets:");
    std::map<AddressPortPair, const ServerConfig *>::const_iterator servers;
    for (servers = default_servers.begin(); servers != default_servers.end(); ++servers) {
        AddressPortPair server = servers->first;
        try {
            DEBUG_PRINT(BG_GRAY, " ip: %s, port: %s", server.first.c_str(), server.second.c_str());
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
    int close_ret = close(fd);
    if (close_ret == CLOSE_ERROR) {
        std::cout << CYAN << "close error" << RESET << std::endl;  // todo: log
    }
}


Result<IOMultiplexer *, std::string> Server::create_io_multiplexer_fds() {
    try {
        IOMultiplexer *fds = new Select();
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
        management_timeout_events();
        set_io_timeout();
        // sleep(1);
        ServerResult fd_ready_result = this->fds_->get_io_ready_fd();
		if (fd_ready_result.is_err()) {
            const std::string error_msg = fd_ready_result.err_value();
            DEBUG_SERVER_PRINT("error: %s", error_msg.c_str());
            continue;
            // return ServerResult::err(error_msg);
		}
		int ready_fd = fd_ready_result.ok_value();
		if (ready_fd == IO_TIMEOUT) {
            if (this->echo_mode_on_) {
                break;
            } else {
                continue;
            }
		}

        ServerResult event_result = process_event(ready_fd);
		if (event_result.is_err()) {
            const std::string error_msg = event_result.err_value();
            DEBUG_PRINT(BG_RED, "[Error]: %s", error_msg.c_str());
            // return ServerResult::err(error_msg);
		}
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
        // DEBUG_SERVER_PRINT("read_fd read -> write");
        this->fds_->clear_fd(fd);
        this->fds_->register_write_fd(fd);
        // std::cout << RED << "update write fd: " << fd << RESET << std::endl;
    }
}

// fds client, cgi
// client_events
// active_client_time_manager
// idling_clientntime_manager
// cgi_events
// cgi_time_manager
// cgi_fd, process
void Server::delete_event(std::map<Fd, Event *>::iterator event) {
    Event *client_event = event->second;
    int client_fd = client_event->client_fd();
    DEBUG_SERVER_PRINT("[delete event] fd: %d (L:%d)", client_fd, __LINE__);

    clear_cgi_fds_from_event_manager(*client_event);
    delete client_event;  // cgi kill

    this->fds_->clear_fd(client_fd);
    this->client_events_.erase(client_fd);

    std::set<FdTimeoutLimitPair>::iterator itr;
    itr = find_fd_in_timeout_pair(client_fd, this->idling_client_time_manager_);
    if (itr != this->idling_client_time_manager_.end()) {
        DEBUG_SERVER_PRINT("[delete event] clear: idling_client_timeout_manager (L:%d)", __LINE__);
        this->idling_client_time_manager_.erase(itr);
    }

    itr = find_fd_in_timeout_pair(client_fd, this->active_client_time_manager_);
    if (itr != this->active_client_time_manager_.end()) {
        DEBUG_SERVER_PRINT("[delete event] clear: active_client_timeout_manager (L:%d)", __LINE__);
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


void Server::clear_events() {
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
        this->cgi_time_manager_.insert(FdTimeoutLimitPair(timeout_limit, write_fd));
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
        this->cgi_time_manager_.insert(FdTimeoutLimitPair(timeout_limit, read_fd));
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
