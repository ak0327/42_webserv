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
      status_code_(StatusOk),
      request_(NULL),
      response_(NULL),
      request_max_body_size_(0),
      client_listen_(client_listen) {}


ClientSession::~ClientSession() {
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


void ClientSession::close_client_fd() {
    if (this->client_fd_ != INIT_FD) {
        close(this->client_fd_);
        this->client_fd_ = INIT_FD;
    }
}


// -----------------------------------------------------------------------------


bool is_continue_recv(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == Continue;
}


bool is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == PrepareNextProc;
}


bool is_executing_cgi(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == ExecutingCgi;
}


// status code update in this func if error occurred
SessionResult ClientSession::process_client_event() {
    ProcResult recv_result, send_result;
    Result<ProcResult, StatusCode> request_result;
    Result<ProcResult, StatusCode> response_result, response_body_result;

    switch (this->session_state_) {
        case kSessionInit: {
            DEBUG_SERVER_PRINT("   Session: 0 SessionInit");
            this->session_state_ = kReceivingRequest;
        }
        // fallthrough

        case kReceivingRequest: {
            DEBUG_SERVER_PRINT("   Session: 1 Recv");
            recv_result = recv_http_request();
            if (recv_result == FatalError) {
                return SessionResult::err("fatal error");  // client close
            }
            if (recv_result == Continue) {
                return SessionResult::ok(Continue);
            }
            this->session_state_ = kParsingRequest;
        }
        // fallthrough

        case kParsingRequest: {
            DEBUG_SERVER_PRINT("   Session: 2 ParsingRequest");
            request_result = parse_http_request();
            if (is_continue_recv(request_result)) {
                DEBUG_SERVER_PRINT("     recv continue(process_client_event)");
                this->session_state_ = kReceivingRequest;
                return SessionResult::ok(Continue);
            }
            if (request_result.is_err()) {
                this->status_code_ = request_result.get_err_value();
            }
            this->session_state_ = kExecutingMethod;
        }
        // fallthrough

        case kCreatingResponse: {
            response_result = create_http_response();
            if (is_executing_cgi(response_result)) {
                this->session_state_ = kExecutingCGI;
                return SessionResult::ok(ExecutingCgi);
            }
            if (response_result.is_err()) {
                this->status_code_ = response_result.get_err_value();
                DEBUG_SERVER_PRINT("    request error2, status: %d", this->response_->get_status_code());
            }
        }

        case kSendingResponse: {
            DEBUG_SERVER_PRINT("   Session: 6 SendingResponse");
            send_result = send_http_response();
            if (send_result == Failure) {
                DEBUG_SERVER_PRINT("    request error4");
                this->session_state_ = kSessionError;
                return SessionResult::err("[Server Error] send");  // todo: tmp
            }
            this->session_state_ = kSessionCompleted;
            return SessionResult::ok(Success);  // todo: error_page ok
        }

        default:
            // kReadingFile, kExecutingCGI -> process_file_event()
            break;
    }
    return SessionResult::ok(Success);
}


// -----------------------------------------------------------------------------


ProcResult ClientSession::recv_http_request() {
    if (!this->request_) {
        try {
            this->request_ = new HttpRequest();
        }
        catch (const std::exception &e) {
            return FatalError;
        }
    }

    std::size_t recv_size = this->request_->recv_to_buf(this->client_fd_);
    return 0 < recv_size ? Success : Continue;
}


// -----------------------------------------------------------------------------


// todo: mv to request ?
Result<ProcResult, StatusCode> ClientSession::parse_http_request() {
    Result<ProcResult, StatusCode> parse_result;
    StatusCode error_code;
    DEBUG_SERVER_PRINT("               ParsingRequest start");

#ifdef ECHO
    (void)error_code;
    this->session_state_ = kCreatingResponseBody;
#else
    if (this->request_->get_parse_phase() == ParsingRequestLine
        || this->request_->get_parse_phase() == ParsingRequestHeaders) {
        DEBUG_SERVER_PRINT("               ParsingRequest 1");
        parse_result = this->request_->parse_start_line_and_headers();
        if (parse_result.is_err()) {
            DEBUG_SERVER_PRINT("               ParsingRequest 2");
            DEBUG_SERVER_PRINT("    request start_line_and_headers error, status: %d", parse_result.get_err_value());
            error_code = parse_result.get_err_value();
            return Result<ProcResult, StatusCode>::err(error_code);
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 3");
            DEBUG_SERVER_PRINT("     recv continue(parse_http_request)");
            return Result<ProcResult, StatusCode>::ok(Continue);
        }

        DEBUG_SERVER_PRINT("               ParsingRequest 4");
        Result<ProcResult, std::string> update_result = update_config_params();
        if (update_result.is_err()) {
            DEBUG_SERVER_PRINT("               ParsingRequest 5");
            DEBUG_SERVER_PRINT("    request error config update error");
            return Result<ProcResult, StatusCode>::err(NotFound);  // todo: code?
        }
        this->request_->set_parse_phase(ParsingRequestBody);
    }

    if (this->request_->get_parse_phase() == ParsingRequestBody) {
        DEBUG_SERVER_PRINT("               ParsingRequest 6");
        parse_result = this->request_->parse_body();
        if (parse_result.is_err()) {
            DEBUG_SERVER_PRINT("               ParsingRequest 7");
            error_code = parse_result.get_err_value();
            DEBUG_SERVER_PRINT("    request body error, status: %d", error_code);
            return Result<ProcResult, StatusCode>::err(error_code);
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 8");
            return Result<ProcResult, StatusCode>::ok(Continue);
        }
        DEBUG_SERVER_PRINT("               ParsingRequest 9");
    }
#endif
    return Result<ProcResult, StatusCode>::ok(Success);
}


// -----------------------------------------------------------------------------


Result<ProcResult, StatusCode> ClientSession::create_http_response() {
    Result<ProcResult, StatusCode> method_result, body_result;

    switch (this->session_state_) {
        case kExecutingMethod: {
            DEBUG_SERVER_PRINT("   Session: 3 CreatingResponse");
            DEBUG_SERVER_PRINT("    status(requ): %d", this->request_->get_status_code());
            method_result = execute_each_method();  // todo: rename
            if (method_result.is_ok() && method_result.get_ok_value() == ExecutingCgi) {
                this->session_state_ = kExecutingCGI;
                return Result<ProcResult, StatusCode>::ok(ExecutingCgi);
            }
            if (method_result.is_err()) {
                this->status_code_ = method_result.get_err_value();
                DEBUG_SERVER_PRINT("    request error2, status: %d", this->response_->get_status_code());
            }
        }
        // fallthrough

        case kCreatingResponseBody: {
#ifdef ECHO
            this->response_->create_echo_msg(this->request_->get_buf());
#else
            body_result = this->response_->create_response_message(this->status_code_);
            if (body_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error3, status: %d", body_result.get_err_value());
                // this->status_code_ = body_result.get_err_value();  // todo: status?
            }
#endif
            this->session_state_ = kSendingResponse;
            break;
        }

        case kCreatingCGIBody: {
            DEBUG_SERVER_PRINT("   Session: 5 CreatingCGIBody");
            body_result = this->response_->create_cgi_body();
            if (body_result.is_err()) {
                DEBUG_SERVER_PRINT("    request error3, status: %d", body_result.get_err_value());
                this->status_code_ = body_result.get_err_value();
            }
            this->session_state_ = kCreatingResponseBody;
            break;
        }

        default:
            break;
    }
    return Result<ProcResult, StatusCode>::ok(Success);
}


// -----------------------------------------------------------------------------


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


    Result<HostPortPair, StatusCode> get_request_host = this->request_->get_server_info();
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
#ifdef ECHO
    this->request_->set_max_body_size(ConfigInitValue::kDefaultBodySize);
#else
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
    std::size_t max_body_size = body_size_result.get_ok_value();
    this->request_->set_max_body_size(max_body_size);
#endif
    return SessionResult::ok(Success);
}


// -----------------------------------------------------------------------------


Result<ProcResult, StatusCode> ClientSession::execute_each_method() {
#ifdef ECHO
    try {
        HttpRequest request;
        ServerConfig config;
        this->response_ = new HttpResponse(request, config);
    }
    catch (const std::exception &e) {
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << err_info << std::endl;
        return Result<ProcResult, StatusCode>::err(InternalServerError);
    }
    return Result<ProcResult, StatusCode>::ok(Success);
#else
    try {
        this->response_ = new HttpResponse(*this->request_, this->server_config_);
        // std::cout << CYAN << "     response_message[" << this->http_response_->get_response_message() << "]" << RESET << std::endl;
    }
    catch (const std::exception &e) {
        const std::string err_info = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << err_info << std::endl;
        return Result<ProcResult, StatusCode> ::err(InternalServerError);
    }
    return this->response_->exec_method();
#endif
}


ProcResult ClientSession::send_http_response() {
    std::vector<unsigned char>response_msg = this->response_->get_response_message();
    std::string msg_for_debug(response_msg.begin(), response_msg.end());

    DEBUG_SERVER_PRINT("   send start");
    DEBUG_SERVER_PRINT("    send_msg[%s]", msg_for_debug.c_str());

    errno = 0;
    if (send(this->client_fd_, response_msg.data(), response_msg.size(), FLAG_NONE) == SEND_ERROR) {
        return Failure;
    }
    DEBUG_SERVER_PRINT("   send end");
    return Success;
}


SessionResult ClientSession::process_file_event() {
    Result<ProcResult, StatusCode> cgi_result;

    switch (this->session_state_) {
        case kReadingFile:
            // todo
            break;

        case kExecutingCGI:
            cgi_result = this->response_->recv_cgi_result();
            if (cgi_result.is_err()) {
                this->session_state_ = kSessionError;
                this->status_code_ = InternalServerError;  // todo: code?
                return SessionResult::err("error: file event error");
            }
            if (is_continue_recv(cgi_result)) {
                return SessionResult::ok(Continue);
            }
            this->session_state_ = kCreatingResponse;
            break;

        default:
            std::cerr << "Unknown session state." << std::endl;
            return SessionResult::err("error: unknown session state in file event");
    }
    return SessionResult::ok(Success);
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
