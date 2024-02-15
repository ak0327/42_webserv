#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <utility>
#include "ClientSession.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "StringHandler.hpp"

// recv request
//  host -> ClientSession

// create response
//  method
//   GET    -> read  / CGI
//   POST   -> write / CGI
//   DELETE -> delete?

// send response

ClientSession::ClientSession(int socket_fd, int client_fd, const Configuration &config)
    : socket_fd_(socket_fd),
      client_fd_(client_fd),
      file_fd_(INIT_FD),
      config_(config),
      server_info_(),
      server_config_(),
      session_state_(kSessionInit),
      http_request_(NULL),
      http_response_(NULL) {}


ClientSession::~ClientSession() {
    close_file_fd();

    if (this->http_request_) {
        delete this->http_request_;
        this->http_request_ = NULL;
    }

    if (this->http_response_) {
        delete this->http_response_;
        this->http_response_ = NULL;
    }
}


void ClientSession::close_file_fd() {
    if (this->file_fd_ != INIT_FD) {
        close(this->file_fd_);
        this->file_fd_ = INIT_FD;
    }
}


SessionResult ClientSession::process_client_event() {
    Result<std::string, std::string> recv_result;
    SessionResult request_result, response_result, send_result;

    while (true) {
        switch (this->session_state_) {
            case kSessionInit:
                std::cout << RED << "   session: 0 SessionInit" << RESET << std::endl;
                this->session_state_ = kReadingRequest;  // jump
                continue;
                // break;

            case kAccepted:
                std::cout << RED << "   session: 0 Accepted" << RESET << std::endl;
                this->session_state_ = kReadingRequest;  // jump
                continue;
                // break;

            case kReadingRequest:
                std::cout << RED << "   session: 1 ReadingRequest" << RESET << std::endl;
                request_result = parse_http_request();
                if (request_result.is_err()) {
                    const std::string error_msg = request_result.get_err_value();
                    return SessionResult::err(error_msg);
                }
                this->session_state_ = kCreatingResponse;  // jump
                continue;

            case kCreatingResponse:
                std::cout << RED << "   session: 2 CreatingResponse" << RESET << std::endl;
                response_result = create_http_response();
                if (response_result.is_err()) {
                    const std::string error_msg = response_result.get_err_value();
                    return SessionResult::err(error_msg);
                }
                this->session_state_ = kSendingResponse;
                break;

            case kReadingFile:
                // process_file_event()
                break;

            case kExecutingCGI:
                // process_file_event
                break;

            case kSendingResponse:
                std::cout << RED << "   session: 3 SendingResponse" << RESET << std::endl;

                send_result = send_response();
                if (send_result.is_err()) {
                    std::cout << CYAN << "     error 4" << RESET << std::endl;
                    const std::string err_info = CREATE_ERROR_INFO_STR(send_result.get_err_value());
                    return SessionResult::err("[Server Error] recv: " + err_info);
                }
                this->session_state_ = kCompleted;
                break;

            case kCompleted:
                break;

            default:
                std::cerr << "Unknown session state: " << this->session_state_ << std::endl;
                return SessionResult::err("error: unknown session state in client event");
        }
        return SessionResult::ok(OK);
    }
}


Result<AddressPortPair, std::string> ClientSession::get_address_port_pair() const {
    struct sockaddr_in addr = {};
    socklen_t addr_len = sizeof(addr);

    errno = 0;
    if (getsockname(this->socket_fd_, (struct sockaddr *)&addr, &addr_len) == -1) {
        const std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        return Result<AddressPortPair, std::string>::err(error_msg);
    }

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
    int port = ntohs(addr.sin_port);
    AddressPortPair pair = std::make_pair(std::string(ip), StringHandler::to_string(port));
    return Result<AddressPortPair, std::string>::ok(pair);
}


Result<ServerConfig, std::string> ClientSession::get_server_config() const {
    // config
    Result<AddressPortPair, std::string> address_result = get_address_port_pair();
    if (address_result.is_err()) {
        const std::string error_msg = address_result.get_err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    AddressPortPair address_port_pair = address_result.get_ok_value();

    Result<HostPortPair, int> get_info_result = this->http_request_->get_server_info();
    if (get_info_result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Fail to get host from Host header");
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    HostPortPair host_port_pair = get_info_result.get_ok_value();

    Result<ServerConfig, std::string> config_result = config_.get_server_config(address_port_pair, host_port_pair);
    if (config_result.is_err()) {
        const std::string error_msg = config_result.get_err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    ServerConfig server_config = config_result.get_ok_value();
    return Result<ServerConfig, std::string>::ok(server_config);
}


SessionResult ClientSession::parse_http_request() {
    try {
        Result<std::string, std::string> recv_result = recv_request();
        if (recv_result.is_err()) {
            const std::string err_info = CREATE_ERROR_INFO_STR(recv_result.get_err_value());
            return SessionResult::err("[Server Error] recv: " + err_info);
        }
        this->recv_message_ = recv_result.get_ok_value();
        DEBUG_SERVER_PRINT("connected. recv:[%s]", this->recv_message_.c_str());

        this->http_request_ = new HttpRequest(this->recv_message_);

        Result<int, std::string> header_result = this->http_request_->parse_request_header(this->client_fd_);
        if (header_result.is_err()) {
            const std::string error_msg = header_result.get_err_value();
            return SessionResult::err(error_msg);
        }

        // config
        Result<ServerConfig, std::string> config_result = ClientSession::get_server_config();
        if (config_result.is_err()) {
            const std::string error_msg = header_result.get_err_value();
            return SessionResult::err(error_msg);
        }
        this->server_config_ = config_result.get_ok_value();

        return SessionResult::ok(OK);

        // todo: vvv
        // Result<int, std::string> request_line_result = this->http_request_->parse_request_line(this->client_fd_);
        // if (request_line_result.is_err()) {
        //     const std::string error_msg = request_line_result.get_err_value();
        //     return SessionResult::err(error_msg);
        // }
        //
        // Result<int, std::string> header_result = this->http_request_->parse_request_header(this->client_fd_);
        // if (header_result.is_err()) {
        //     const std::string error_msg = header_result.get_err_value();
        //     return SessionResult::err(error_msg);
        // }
        //
        // // config
        // Result<ServerConfig *, std::string> config_result = ClientSession::get_server_config();
        // if (config_result.is_err()) {
        //     const std::string error_msg = header_result.get_err_value();
        //     return SessionResult::err(error_msg);
        // }
        // this->server_config_ = config_result.get_ok_value();
        //
        // // create_response
        // Result<int, std::string> body_result = this->http_request_->parse_request_body(this->client_fd_, *this->server_config_);
        // if (body_result.is_err()) {
        //     const std::string error_msg = body_result.get_err_value();
        //     return SessionResult::err(error_msg);
        // }
        // return SessionResult::ok(OK);
    }
    catch (const std::exception &e) {
        std::cout << CYAN << "     error 2" << RESET << std::endl;
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return SessionResult::err(err_info);
    }
}


Result<int, std::string> ClientSession::create_http_response() {
    try {
        this->http_response_ = new HttpResponse(*this->http_request_);
        // std::cout << CYAN << "     response_message[" << this->http_response_->get_response_message() << "]" << RESET << std::endl;
    }
    catch (const std::exception &e) {
        std::cout << CYAN << "     error 3" << RESET << std::endl;
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        return SessionResult::err(err_info);
    }
    return SessionResult::ok(OK);
}

Result<std::string, std::string> ClientSession::recv_request() {
    char		buf[BUFSIZ + 1];
    ssize_t		recv_size;
    std::string	recv_msg;

    // std::cout << CYAN << "server recv start" << RESET << std::endl;

    while (true) {
        errno = 0;
        recv_size = recv(this->client_fd_, buf, BUFSIZ, FLAG_NONE);
        // todo: flg=FLAG_NONE, errno=EAGAIN -> continue?
        // std::cout << CYAN << " server recv_size:" << recv_size << RESET << std::endl;
        if (recv_size == 0) {
        	break;
        }
        if (recv_size == RECV_ERROR || recv_size > BUFSIZ) {
            const std::string error_info = CREATE_ERROR_INFO_ERRNO(errno);
            return Result<std::string, std::string>::err(error_info);
        }
        buf[recv_size] = '\0';
        // std::cout << CYAN << " server: recv[" << std::string(buf, recv_size) << "]" << RESET << std::endl;

        recv_msg.append(std::string(buf, recv_size));
        if (recv_size < BUFSIZ) {
            break;
        }
    }
    // std::cout << CYAN << " server: recv_message[" << recv_msg << "]" << RESET << std::endl;
    // std::cout << CYAN << "server recv end" << RESET << std::endl;
    return Result<std::string, std::string>::ok(recv_msg);
}


SessionResult ClientSession::send_response() {
    std::string response_message = this->http_response_->get_response_message();
    // std::size_t	message_len = this->http_response_->get_response_size();
    // std::string response_message = this->recv_message_;

    // std::cout << CYAN << "server send start" << RESET << std::endl;
    // std::cout << CYAN << " server: send[" << response_message << "]" << RESET << std::endl;

    errno = 0;
    if (send(this->client_fd_, response_message.c_str(), response_message.size(), FLAG_NONE) == SEND_ERROR) {
        return SessionResult::err(CREATE_ERROR_INFO_ERRNO(errno));
    }
    // std::cout << CYAN << "server send end" << RESET << std::endl;
    return SessionResult::ok(OK);
}


SessionResult ClientSession::process_file_event() {
    SessionResult result;

    switch (this->session_state_) {
        case kReadingFile:

            // continue -> return

            break;
        case kExecutingCGI:

            // continue -> return

            break;
        default:
            // std::cerr << "Unknown session state." << std::endl;
            return SessionResult::err("error: unknown session state in file event");
    }
    if (result.is_err()) {
        return SessionResult::err("error: file event error");
    }
    this->session_state_ = kCreatingResponse;
    return SessionResult::ok(OK);
}


int ClientSession::get_file_fd() const { return this->file_fd_; }
int ClientSession::get_client_fd() const { return this->client_fd_; }
SessionState ClientSession::get_session_state() const { return this->session_state_; }
bool ClientSession::is_session_completed() const { return this->session_state_ == kCompleted; }
