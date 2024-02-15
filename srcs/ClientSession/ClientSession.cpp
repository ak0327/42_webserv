#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include "ClientSession.hpp"
#include "Debug.hpp"
#include "Error.hpp"

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
      server_info_(),
      server_config_(NULL),
      config_(config),
      session_state_(kSessionInit),
      http_request_(NULL),
      http_response_(NULL) {}


ClientSession::~ClientSession() {
    close_file_fd();

    delete this->http_request_;
    this->http_request_ = NULL;

    delete this->http_response_;
    this->http_response_ = NULL;
}


void ClientSession::close_file_fd() {
    if (this->file_fd_ != INIT_FD) {
        close(this->file_fd_);
        this->file_fd_ = INIT_FD;
    }
}


SessionResult ClientSession::process_client_event() {
    Result<std::string, std::string> recv_result;
    SessionResult send_result;

    while (true) {
        switch (this->session_state_) {
            case kSessionInit:
                this->session_state_ = kReadingRequest;
                continue;

            case kAccepted:
                this->session_state_ = kReadingRequest;
                continue;

            case kReadingRequest:
                std::cout << CYAN << "   session: 1 request" << RESET << std::endl;

                recv_result = recv_request();
                if (recv_result.is_err()) {
                    std::cout << CYAN << "     error 1" << RESET << std::endl;
                    const std::string err_info = CREATE_ERROR_INFO_STR(recv_result.get_err_value());
                    return SessionResult::err("[Server Error] recv: " + err_info);
                }
                this->recv_message_ = recv_result.get_ok_value();
                DEBUG_SERVER_PRINT("connected. recv:[%s]", this->recv_message_.c_str());

                // request header
                // Host
                // config
                // create_response
                try {
                    this->http_request_ = new HttpRequest(this->recv_message_);
                    std::cout << CYAN << "     recv_message[" << this->recv_message_ << "]" << RESET << std::endl;
                    std::cout << CYAN << "     status_code [" << this->http_request_->get_status_code() << "]" << RESET << std::endl;
                }
                catch (const std::exception &e) {
                    std::cout << CYAN << "     error 2" << RESET << std::endl;
                    const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
                    return SessionResult::err(err_info);
                }

                this->session_state_ = kCreatingResponse;
                continue;

            case kCreatingResponse:
                std::cout << CYAN << "   session: 2 response" << RESET << std::endl;

                try {
                    this->http_response_ = new HttpResponse(*this->http_request_);
                }
                catch (const std::exception &e) {
                    std::cout << CYAN << "     error 3" << RESET << std::endl;
                    const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
                    return SessionResult::err(err_info);
                }

                this->session_state_ = kSendingResponse;

                // break;
                continue;

            case kReadingFile:
                break;

            case kExecutingCGI:
                break;

            case kSendingResponse:
                std::cout << CYAN << "   session: 3 send" << RESET << std::endl;

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


Result<std::string, std::string> ClientSession::recv_request() {
    char		buf[BUFSIZ + 1];
    ssize_t		recv_size;
    std::string	recv_msg;

    std::cout << CYAN << "server recv start" << RESET << std::endl;

    while (true) {
        errno = 0;
        recv_size = recv(this->client_fd_, buf, BUFSIZ, FLAG_NONE);
        // todo: flg=FLAG_NONE, errno=EAGAIN -> continue?
        std::cout << CYAN << " server recv_size:" << recv_size << RESET << std::endl;
        // if (recv_size == 0) {
        // 	break;
        // }
        if (recv_size == RECV_ERROR || recv_size > BUFSIZ) {
            const std::string error_info = CREATE_ERROR_INFO_ERRNO(errno);
            return Result<std::string, std::string>::err(error_info);
        }
        buf[recv_size] = '\0';
        std::cout << CYAN << " server: recv[" << std::string(buf, recv_size) << "]" << RESET << std::endl;

        recv_msg.append(std::string(buf, recv_size));
        if (recv_size < BUFSIZ) {
            break;
        }
    }
    std::cout << CYAN << " server: recv_message[" << recv_msg << "]" << RESET << std::endl;
    std::cout << CYAN << "server recv end" << RESET << std::endl;
    return Result<std::string, std::string>::ok(recv_msg);
}


SessionResult ClientSession::send_response() {
    std::string response_message = this->http_response_->get_response_message();
    std::size_t	message_len = this->http_response_->get_response_size();

    std::cout << CYAN << "server send start" << RESET << std::endl;
    std::cout << CYAN << " server: send[" << response_message << "]" << RESET << std::endl;

    errno = 0;
    if (send(this->client_fd_, response_message.c_str(), message_len, FLAG_NONE) == SEND_ERROR) {
        return SessionResult::err(strerror(errno));
    }
    std::cout << CYAN << "server send end" << RESET << std::endl;
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
            std::cerr << "Unknown session state." << std::endl;
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
