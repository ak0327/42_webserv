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


ServerResult Server::process_event(int ready_fd) {
    if (is_socket_fd(ready_fd)) {
        // DEBUG_SERVER_PRINT("  ready_fd=socket ready_fd: %d -> create_event()", ready_fd);
        return create_event(ready_fd);
    }
    if (is_client_fd(ready_fd)) {
        // DEBUG_SERVER_PRINT("  ready_fd=client ready_fd: %d -> handle_client_event()", ready_fd);
        return handle_client_event(ready_fd);
    }
    if (is_cgi_fd(ready_fd)) {
        // DEBUG_SERVER_PRINT("  ready_fd=cgi ready_fd: %d -> handle_cgi_event()", ready_fd);
        return handle_cgi_event(ready_fd);
    }
    const std::string error_msg = CREATE_ERROR_INFO_CSTR("error: unknown fd");
    return ServerResult::err(error_msg);
}


bool Server::is_socket_fd(int fd) const {
    return this->sockets_.find(fd) != this->sockets_.end();
}


bool Server::is_client_fd(int fd) {
    std::map<Fd, Event *>::iterator event = this->client_events_.find(fd);
    return event != this->client_events_.end();
}


bool Server::is_cgi_fd(int fd) {
    std::map<Fd, Event *>::iterator event = this->cgi_events_.find(fd);
    return event != this->cgi_events_.end();
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::create_event(int socket_fd) {
    struct sockaddr_storage client_addr = {};
    ServerResult accept_result = accept_connect_fd(socket_fd, &client_addr);
    if (accept_result.is_err()) {
        const std::string error_msg = accept_result.err_value();
        return ServerResult::err(error_msg);
    }
    if (accept_result.ok_value() == ERR) {  // exceed max connection
        return ServerResult::ok(OK);
    }
    int connect_fd = accept_result.ok_value();
    Result<int, std::string> non_block = Socket::set_fd_to_nonblock(connect_fd);
    if (non_block.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR(non_block.err_value());
        return ServerResult::err(error_msg);
    }

    // std::cout << CYAN << " accept fd: " << connect_fd << RESET << std::endl;

    if (this->client_events_.find(connect_fd) != this->client_events_.end()) {
        return ServerResult::err("error: read_fd duplicated");  // ?
    }
    try {
        // std::cout << CYAN << " new_session created" << RESET << std::endl;
        AddressPortPair client_listen = Server::get_client_listen(client_addr);

        std::ostringstream oss; oss << client_listen;
        DEBUG_PRINT(GRAY_BACK, "connect_client: %s", oss.str().c_str());

        Event *new_session = new Event(socket_fd,
                                       connect_fd,
                                       client_listen,
                                       this->config_,
                                       &this->sessions_,
                                       this->echo_mode_on_);
        if (new_session->init_request_obj() == Failure) {
            delete new_session;
            throw std::runtime_error("HttpRequest");
        }

        if (MAX_CONNECTION <= this->client_events_.size()) {
            DEBUG_PRINT(GRAY_BACK, "exceed max_connaction: events: %zu", this->client_events_.size());
            if (new_session->set_to_max_connection_event() == Failure) {
                delete new_session;
                DEBUG_PRINT(RED, "error: create response failure");
                return ServerResult::ok(OK);
            }
            update_fd_type(connect_fd, kReadFd, kWriteFd);
        }

        // DEBUG_SERVER_PRINT("new_clilent: %p", new_session);
        // std::cout << CYAN << " event start" << connect_fd << RESET << std::endl;
        handle_active_client_timeout(new_session);

        this->client_events_[connect_fd] = new_session;

        return ServerResult::ok(OK);
    }
    catch (const std::exception &e) {
        std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory: " + std::string(e.what()));
        return ServerResult::err(err_info);
    }
}


ServerResult Server::accept_connect_fd(int socket_fd,
                                       struct sockaddr_storage *client_addr) {
    const int MAX_SESSION = SOMAXCONN;
    (void)MAX_SESSION;

    // if (MAX_SESSION <= this->client_fds_.size()) {
    //     std::cerr << "[Server Error] exceed max connection" << std::endl;
    //     return ServerResult::ok(ERR);  // todo: continue, ok?
    // }

    SocketResult accept_result = Socket::accept(socket_fd, client_addr);
    if (accept_result.is_err()) {
        const std::string error_msg = accept_result.err_value();
        return ServerResult::err(error_msg);
    }
    int connect_fd = accept_result.ok_value();
    // DEBUG_SERVER_PRINT("  accepted connect read_fd: %d", connect_fd);

    ServerResult fd_register_result = this->fds_->register_read_fd(connect_fd);
    if (fd_register_result.is_err()) {
        std::string err_info = CREATE_ERROR_INFO_STR(
                fd_register_result.err_value());
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


AddressPortPair Server::get_client_listen(const struct sockaddr_storage &client_addr) {
    char ip[INET6_ADDRSTRLEN];
    std::string address, port;
    std::ostringstream port_stream;
    struct sockaddr_in *addr_in;
    struct sockaddr_in6 *addr_in6;

    switch (client_addr.ss_family) {
        case AF_INET: {
            addr_in = (struct sockaddr_in *)&client_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
            address = ip;
            port_stream << ntohs(addr_in->sin_port);
            break;
        }

        case AF_INET6: {
            addr_in6 = (struct sockaddr_in6 *)&client_addr;
            if (IN6_IS_ADDR_V4MAPPED(&addr_in6->sin6_addr)) {
                inet_ntop(AF_INET, &addr_in6->sin6_addr.s6_addr[12], ip, INET_ADDRSTRLEN);
                address = ip;
            } else {
                inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, sizeof(ip));
                address = ip;
            }
            port_stream << ntohs(addr_in6->sin6_port);
            break;
        }

        default: {
            address = "unknown address";
            port = "unknown port";
        }
    }

    if (port.empty()) {
        port = port_stream.str();
    }
    AddressPortPair pair(address, port);
    DEBUG_SERVER_PRINT("address: %s, port: %s", address.c_str(), port.c_str());
    return pair;
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::handle_client_event(int client_fd) {
    std::map<Fd, Event *>::iterator event = this->client_events_.find(client_fd);
    if (event == this->client_events_.end())  {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: fd is not client");
        return ServerResult::err(error_msg);
    }

    Event *client_event = event->second;

    if (is_idling_client(client_fd)) {
        clear_from_keepalive_clients(client_fd);
        handle_active_client_timeout(client_event);
    }

    // DEBUG_SERVER_PRINT("process_event -> process_client_event");
    EventResult event_result = client_event->process_client_event();
    if (event_result.is_err()) {
        // fatal error occurred -> server shut down
        const std::string error_msg = event_result.err_value();
        return ServerResult::err(error_msg);
    }


    handle_active_client_timeout(client_event);
    switch (event_result.ok_value()) {
        case Success: {
            break;
        }
        case Continue: {
            // Receiving -> set client_header_timeout / client_body_timeout

            std::ostringstream oss; oss << client_event;
            // DEBUG_SERVER_PRINT("process_event(client) -> recv continue: %s", oss.str().c_str());
            return ServerResult::ok(OK);
        }
        case ExecutingCgi: {
            std::ostringstream oss; oss << client_event;
            // DEBUG_SERVER_PRINT("process_event(client) -> executing_cgi: %s", oss.str().c_str());

            register_cgi_write_fd_to_event_manager(&client_event);
            // register_cgi_fds_to_event_manager(&client_event);
            this->fds_->clear_fd(client_fd);
            return ServerResult::ok(OK);
        }
        case Idling: {
            return ServerResult::ok(OK);
        }
        case ConnectionClosed: {
            DEBUG_SERVER_PRINT("[handle_client_event] connection closed (L:%d)", __LINE__);
            delete_event(event);
            return ServerResult::ok(OK);
        }
        default:
            // std::ostringstream oss; oss << client_event;
            // DEBUG_SERVER_PRINT("process_event(client) -> error occurred, delete event: %s", oss.str().c_str());
            delete_event(event);
            return ServerResult::ok(OK);
    }

    switch (client_event->event_phase()) {
        case kExecutingMethod: {
            return handle_client_event(client_fd);
        }
        case kSendingResponse: {
            std::ostringstream oss; oss << client_event;
            DEBUG_SERVER_PRINT("process_event(client) -> sending response: %s", oss.str().c_str());
            update_fd_type(client_fd, kReadFd, kWriteFd);
            break;
        }
        case kEventCompleted: {
            std::ostringstream oss; oss << client_event;
            DEBUG_SERVER_PRINT("client event completed: %s", oss.str().c_str());
            if (client_event->is_keepalive()) {
                DEBUG_PRINT(GRAY_BACK, " -> keep-alive %zu sec", this->config_.keepalive_timeout());
                idling_event(client_event);
            } else {
                DEBUG_SERVER_PRINT(" -> close connection");
                delete_event(event);
            }
            break;
        }
        default:
            // todo
            break;
    }

    return ServerResult::ok(OK);
}


////////////////////////////////////////////////////////////////////////////////


ServerResult Server::handle_cgi_event(int cgi_fd) {
    std::map<Fd, Event *>::iterator event = this->cgi_events_.find(cgi_fd);
    if (event == this->client_events_.end())  {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: fd is not cgi");
        return ServerResult::err(error_msg);
    }

    Event *cgi_event = event->second;
    EventResult event_result = cgi_event->process_file_event();

    if (event_result.is_err()) {
        const std::string error_msg = event_result.err_value();
        return ServerResult::err(error_msg);
    }
    switch (event_result.ok_value()) {
        case Success: {
            break;
        }
        case Continue: {
            std::ostringstream oss; oss << cgi_event;
            DEBUG_SERVER_PRINT("process_event(cgi) -> recv continue: %s", oss.str().c_str());
            return ServerResult::ok(OK);
        }
        case ConnectionClosed: {
            // delete_event(event);
            DEBUG_PRINT(RED, "[come here?] connection closed");
            return ServerResult::ok(OK);
        }
        default:
            std::ostringstream oss; oss << cgi_event;
            DEBUG_SERVER_PRINT("[come here?] process_event(cgi) -> error occurred, delete event: %s", oss.str().c_str());

            // delete_event(event);
            return ServerResult::ok(OK);
    }

    switch (cgi_event->event_phase()) {
        case kReceivingCgiResponse: {
            std::ostringstream oss; oss << cgi_event;
            DEBUG_SERVER_PRINT("process_event(cgi) -> [CGI] send fin, recv start: %s", oss.str().c_str());
            int write_fd = cgi_fd;
            clear_fd_from_event_manager(write_fd);
            register_cgi_read_fd_to_event_manager(&cgi_event);
            break;
        }
        case kCreatingCGIBody: {
            std::ostringstream oss; oss << cgi_event;
            DEBUG_SERVER_PRINT("process_event(cgi) -> [CGI] recv fin, create body: %s", oss.str().c_str());

            int write_fd = cgi_fd;
            clear_fd_from_event_manager(write_fd);
            clear_fd_from_event_manager(cgi_event->cgi_read_fd());
            // clear_cgi_fds_from_event_manager(*cgi_event);
            this->fds_->register_write_fd(cgi_event->client_fd());
            return process_event(cgi_event->client_fd());
        }
        default:
            break;
    }
    return ServerResult::ok(OK);
}
