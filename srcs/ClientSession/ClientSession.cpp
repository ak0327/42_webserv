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
#include "HttpResponse.hpp"
#include "StringHandler.hpp"

// recv request
//  host -> ClientSession

// create response
//  method
//   GET    -> read  / CGI
//   POST   -> write / CGI
//   DELETE -> delete?

// send response

ClientSession::ClientSession(int socket_fd,
                             int client_fd,
                             const AddressPortPair &client_listen,
                             const Configuration &config)
    : socket_fd_(socket_fd),
      client_fd_(client_fd),
      config_(config),
      server_info_(),
      server_config_(),
      session_state_(kSessionInit),
      request_(NULL),
      response_(NULL),
      request_max_body_size_(0),
      client_listen_(client_listen) {}


ClientSession::~ClientSession() {
    close_file_fd();
    close_client_fd();
    clear_request();
    clear_response();
}


void ClientSession::clear_request() {
    if (this->request_) {
        delete this->request_;
        this->request_ = NULL;
    }
}

void ClientSession::clear_response() {
    if (this->response_) {
        delete this->response_;
        this->response_ = NULL;
    }
}

void ClientSession::close_file_fd() {
    // if (this->request_ && this->response_->get_cgi_fd() != INIT_FD) {
    //     close(this->cgi_read_fd_);
    //     this->cgi_read_fd_ = INIT_FD;
    // }
}


void ClientSession::close_client_fd() {
    if (this->client_fd_ != INIT_FD) {
        close(this->client_fd_);
        this->client_fd_ = INIT_FD;
    }
}


SessionResult ClientSession::process_client_event() {
    Result<std::string, std::string> recv_result;
    Result<int, StatusCode> request_result, send_result;
    Result<int, StatusCode> create_response_result, response_body_result;

    switch (this->session_state_) {
        case kSessionInit:
            DEBUG_SERVER_PRINT("   session: 0 SessionInit");
            this->session_state_ = kReadingRequest;
            // fallthrough


        case kAccepted:
            DEBUG_SERVER_PRINT("   session: 0 Accepted");
            this->session_state_ = kReadingRequest;
            // fallthrough


        case kReadingRequest:
            DEBUG_SERVER_PRINT("   session: 1 ReadingRequest");
            request_result = parse_http_request();
            if (request_result.is_ok() && request_result.get_ok_value() == CONTINUE) {
                return SessionResult::ok(OK);
            }
            if (request_result.is_err()) {
                this->request_->set_status_code(request_result.get_err_value());  // update status
                DEBUG_SERVER_PRINT("    request error1, status: %d", request_result.get_err_value());
            }
            this->session_state_ = kCreatingResponse;
            // fallthrough


        case kCreatingResponse:
            DEBUG_SERVER_PRINT("   session: 2 CreatingResponse");
            DEBUG_SERVER_PRINT("    status(requ): %d", this->request_->get_status_code());
            create_response_result = create_http_response();  // todo: rename
            if (create_response_result.is_ok() && create_response_result.get_ok_value() == CGI) {
                this->session_state_ = kExecutingCGI;
                return SessionResult::ok(CGI);
            }

            if (create_response_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error2, status: %d", create_response_result.get_err_value());
            }
            this->session_state_ = kCreatingResponseBody;
            // fallthrough


        case kCreatingResponseBody:
            DEBUG_SERVER_PRINT("   session: 3 CreatingResponseBody");
            DEBUG_SERVER_PRINT("    status(requ): %d", this->request_->get_status_code());
#ifdef ECHO
            this->response_->create_echo_msg(this->request_->get_buf());
#else
            response_body_result = this->response_->create_response_message();
            if (response_body_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error3, status: %d", response_body_result.get_err_value());
                // this->session_state_ = kSessionError;
            }
#endif
            this->session_state_ = kSendingResponse;
            return SessionResult::ok(OK);  // todo: error_page ok


        case kCreatingCGIBody:
            DEBUG_SERVER_PRINT("   session: 4 CreatingCGIBody");
            response_body_result = this->response_->create_cgi_body();
            if (response_body_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error3, status: %d", response_body_result.get_err_value());
                // this->session_state_ = kSessionError;
            }
            this->session_state_ = kSendingResponse;
            return SessionResult::ok(OK);  // todo: error_page ok


        case kSendingResponse:
            DEBUG_SERVER_PRINT("   session: 4 SendingResponse");

            send_result = send_response();
            if (send_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error4, status: %d", send_result.get_err_value());
                const std::string err_info = CREATE_ERROR_INFO_STR(send_result.get_err_value());
                this->session_state_ = kSessionError;
                return SessionResult::err("[Server Error] recv: " + err_info);
            }
            this->session_state_ = kSessionCompleted;
            return SessionResult::ok(OK);  // todo: error_page ok


        default:
            // kReadingFile, kExecutingCGI -> process_file_event()
            break;
    }
    return SessionResult::ok(OK);
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
    // DEBUG_PRINT(YELLOW, "get_server_config");
    // DEBUG_PRINT(YELLOW, " address: %s, port:%s", address_port_pair.first.c_str(), address_port_pair.second.c_str());


    Result<HostPortPair, int> get_request_host = this->request_->get_server_info();
    if (get_request_host.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Fail to get host from Host header");
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    HostPortPair host_port_pair = get_request_host.get_ok_value();
    // DEBUG_PRINT(YELLOW, " host: %s, port:%s", host_port_pair.first.c_str(), host_port_pair.second.c_str());

    Result<ServerConfig, std::string> config_result = config_.get_server_config(address_port_pair, host_port_pair);
    if (config_result.is_err()) {
        // DEBUG_PRINT(YELLOW, "get_server_config err");
        const std::string error_msg = config_result.get_err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    // DEBUG_PRINT(YELLOW, "get_server_config ok");
    ServerConfig server_config = config_result.get_ok_value();
    return Result<ServerConfig, std::string>::ok(server_config);
}


SessionResult ClientSession::update_config_params() {
    Result<ServerConfig, std::string> config_result = ClientSession::get_server_config();
    if (config_result.is_err()) {
        const std::string error_msg = config_result.get_err_value();
        return SessionResult::err(error_msg);
    }
    this->server_config_ = config_result.get_ok_value();

    const std::string request_target = this->request_->get_request_target();

    Result<std::size_t, int> body_size_result;
    body_size_result = Configuration::get_max_body_size(server_config_, request_target);
    if (body_size_result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: fail to get client_max_body_size");
        return SessionResult::err(error_msg);
    }
    this->request_max_body_size_ = body_size_result.get_ok_value();
    return SessionResult::ok(OK);
}


Result<int, StatusCode> ClientSession::parse_http_request() {
    try {
        this->request_ = new HttpRequest();
    }
    catch (const std::exception &e) {
        return Result<int, int>::err(STATUS_SERVER_ERROR);
    }
#ifdef ECHO
    this->request_max_body_size_ = ConfigInitValue::kDefaultBodySize;
#else
    // recv_until_empty??
    DEBUG_SERVER_PRINT("    parse_http_request 1");
    Result<int, StatusCode> recv_result = this->request_->recv_request_line_and_header(this->client_fd_);
    if (recv_result.is_err()) {
        DEBUG_SERVER_PRINT("     error 1");
        return Result<int, StatusCode>::err(recv_result.get_err_value());
    }
    if (this->request_->is_buf_empty()) {
        DEBUG_SERVER_PRINT("     buf empty -> continue");
        return Result<int, StatusCode>::ok(CONTINUE);
    }

    DEBUG_SERVER_PRINT("    parse_http_request 2");
    // request line
    Result<int, StatusCode> request_line_result = this->request_->parse_request_line();
    if (request_line_result.is_err()) {
        DEBUG_SERVER_PRINT("     error 2");
        return Result<int, StatusCode>::err(request_line_result.get_err_value());
    }
    DEBUG_SERVER_PRINT("    parse_http_request 3");

    // request header
    Result<int, StatusCode> header_result = this->request_->parse_header();
    if (header_result.is_err()) {
        DEBUG_SERVER_PRINT("     error 3");
        return Result<int, StatusCode>::err(header_result.get_err_value());
    }
    DEBUG_SERVER_PRINT("    parse_http_request 4");
    // config
    Result<int, std::string> update_result = update_config_params();
    if (update_result.is_err()) {
        // todo: status update if not error
        DEBUG_SERVER_PRINT("     error 4");
        // todo: status
        return Result<int, StatusCode>::err(STATUS_NOT_FOUND);  // todo
    }
    DEBUG_SERVER_PRINT("    parse_http_request 5");
#endif
    // body
    Result<int, StatusCode> body_result;
    body_result = this->request_->recv_body(this->client_fd_,
                                            this->request_max_body_size_);
    if (body_result.is_err()) {
        DEBUG_SERVER_PRINT("     error 5");
        return Result<int, StatusCode>::err(body_result.get_err_value());
    }
    DEBUG_SERVER_PRINT("    parse_http_request 6");
    return Result<int, StatusCode>::ok(OK);
}


Result<int, int> ClientSession::create_http_response() {
#ifdef ECHO
    try {
        HttpRequest request;
        ServerConfig config;
        this->response_ = new HttpResponse(request, config);
    }
    catch (const std::exception &e) {
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << err_info << std::endl;
        return Result<int, int> ::err(STATUS_SERVER_ERROR);
    }
    return Result<int, int> ::ok(OK);
#else
    try {
        this->response_ = new HttpResponse(*this->request_, this->server_config_);
        // std::cout << CYAN << "     response_message[" << this->http_response_->get_response_message() << "]" << RESET << std::endl;
    }
    catch (const std::exception &e) {
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << err_info << std::endl;
        return Result<int, int> ::err(STATUS_SERVER_ERROR);
    }
    return this->response_->exec_method();
#endif
}


Result<int, int> ClientSession::send_response() {
    // std::size_t	message_len = this->http_response_->get_response_size();
    std::vector<unsigned char>response_msg = this->response_->get_response_message();
    std::string msg_for_debug(response_msg.begin(), response_msg.end());

    DEBUG_SERVER_PRINT("   send start");
    DEBUG_SERVER_PRINT("    send_msg[%s]", msg_for_debug.c_str());

    errno = 0;
    if (send(this->client_fd_, response_msg.data(), response_msg.size(), FLAG_NONE) == SEND_ERROR) {
        return Result<int, int>::err(STATUS_SERVER_ERROR);
    }
    DEBUG_SERVER_PRINT("   send end");
    return Result<int, int>::ok(OK);
}


SessionResult ClientSession::process_file_event() {
    SessionResult result;
    Result<int, int> cgi_result;

    switch (this->session_state_) {
        // case kReadingFile:
        //     todo
            // break;

        case kExecutingCGI:
            cgi_result = this->response_->recv_cgi_result();
            if (cgi_result.is_err()) {
                this->session_state_ = kSessionError;
            } else if (cgi_result.get_ok_value() == OK) {
                this->session_state_ = kCreatingResponseBody;
            }
            break;

        default:
            // std::cerr << "Unknown session state." << std::endl;
            return SessionResult::err("error: unknown session state in file event");
    }
    if (result.is_err()) {
        return SessionResult::err("error: file event error");
    }
    return SessionResult::ok(OK);
}


int ClientSession::get_cgi_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->get_cgi_fd();
}


int ClientSession::get_client_fd() const {
    return this->client_fd_;
}


SessionState ClientSession::get_session_state() const {
    return this->session_state_;
}

void ClientSession::set_session_state(const SessionState &set_state) {
    this->session_state_ = set_state;
}


bool ClientSession::is_session_state_expect_to(const SessionState &expect) const {
    return this->session_state_ == expect;
}


AddressPortPair ClientSession::get_client_listen(const struct sockaddr_storage &client_addr) {
    char ip[INET6_ADDRSTRLEN];
    std::string address, port;
    std::ostringstream port_stream;
    struct sockaddr_in *addr_in;
    struct sockaddr_in6 *addr_in6;

    switch (client_addr.ss_family) {
        case AF_INET:
            addr_in = (struct sockaddr_in *)&client_addr;
            inet_ntop(AF_INET, &addr_in->sin_addr, ip, sizeof(ip));
            address = ip;
            port_stream << ntohs(addr_in->sin_port);
            break;

        case AF_INET6:
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

        default:
            address = "unknown address";
            port = "unknown port";
    }

    if (port.empty()) {
        port = port_stream.str();
    }
    AddressPortPair pair(address, port);
    DEBUG_SERVER_PRINT("address: %s, port: %s", address.c_str(), port.c_str());
    return pair;
}
