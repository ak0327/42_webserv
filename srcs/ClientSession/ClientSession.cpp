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
                             const Config &config)
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


void ClientSession::kill_cgi_process() {
    if (this->response_) {
        this->response_->kill_cgi_process();
    }
}


// todo: unused??
void ClientSession::clear_cgi() {
    if (this->response_) {
        this->response_->clear_cgi();
    }
}


time_t ClientSession::cgi_timeout_limit() const {
    return this->response_ ? this->response_->cgi_timeout_limit() : 0;
}



// -----------------------------------------------------------------------------


// status code update in this func if error occurred
SessionResult ClientSession::process_client_event() {
    DEBUG_SERVER_PRINT("  client_event start");
    switch (this->session_state_) {
        case kSessionInit: {
            DEBUG_SERVER_PRINT("   Session: 0 SessionInit");
            this->set_session_state(kReceivingRequest);
        }
        // fallthrough

        case kReceivingRequest: {
            DEBUG_SERVER_PRINT("   Session: 1 Recv");
            ProcResult recv_result = recv_http_request();
            if (recv_result == FatalError) {
                const std::string error_msg = CREATE_ERROR_INFO_STR("fatal error");
                return SessionResult::err(error_msg);
            } else if (recv_result == Continue) {
                return SessionResult::ok(Continue);
            } else if (recv_result == ConnectionClosed) {
                return SessionResult::ok(ConnectionClosed);
            }
            this->set_session_state(kParsingRequest);
        }
        // fallthrough

        case kParsingRequest: {
            DEBUG_SERVER_PRINT("   Session: 2 ParsingRequest");
            ProcResult request_result = parse_http_request();
            if (request_result == Continue) {
                DEBUG_SERVER_PRINT("     recv continue(process_client_event)");
                this->set_session_state(kReceivingRequest);
                return SessionResult::ok(Continue);
            }
            this->set_session_state(kExecutingMethod);
        }
        // fallthrough

        case kExecutingMethod:
        case kCreatingResponseBody:
        case kCreatingCGIBody: {
            DEBUG_SERVER_PRINT("   Session: 3 CreatingResponse");
            ProcResult response_result = create_http_response();
            if (response_result == ExecutingCgi) {
                this->set_session_state(kExecutingCGI);
                return SessionResult::ok(ExecutingCgi);
            }
            break;
        }

        case kSendingResponse: {
            DEBUG_SERVER_PRINT("   Session: 4 SendingResponse");
            ProcResult send_result = send_http_response();
            if (send_result == Failure) {
                DEBUG_SERVER_PRINT("    request error4");
                this->set_session_state(kSessionError);
                const std::string error_msg = CREATE_ERROR_INFO_STR("error: send");
                return SessionResult::err(error_msg);
            }
            this->set_session_state(kSessionCompleted);
            return SessionResult::ok(Success);  // todo: error_page ok
        }

        default:
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in client event");
            return SessionResult::err(error_msg);
    }
    DEBUG_SERVER_PRINT("  client_event end");
    return SessionResult::ok(Success);
}


// -----------------------------------------------------------------------------


ProcResult ClientSession::recv_http_request() {
    if (!this->request_) {
        try {
            this->request_ = new HttpRequest();
        }
        catch (const std::exception &e) {
            DEBUG_PRINT(RED, "error: fail to memory allocate");  // todo: logging
            return FatalError;
        }
    }

    ssize_t recv_size = this->request_->recv_to_buf(this->client_fd_);
    if (recv_size == 0) {
        return ConnectionClosed;
    }
    return 0 < recv_size ? Success : Continue;
}


// -----------------------------------------------------------------------------


ProcResult ClientSession::parse_http_request() {
    DEBUG_SERVER_PRINT("               ParsingRequest start");
#ifdef ECHO
    this->set_session_state(kCreatingResponseBody);
#else
    if (this->request_->parse_phase() == ParsingRequestLine
        || this->request_->parse_phase() == ParsingRequestHeaders) {
        DEBUG_SERVER_PRINT("               ParsingRequest 1");
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_start_line_and_headers();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.get_err_value();
            DEBUG_SERVER_PRINT("               ParsingRequest 2 error: %d", error_code);
            this->request_->set_status_code(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 3 -> continue");
            return Continue;
        }

        DEBUG_SERVER_PRINT("               ParsingRequest 4");
        Result<ProcResult, std::string> update_result = update_config_params();
        if (update_result.is_err()) {
            DEBUG_SERVER_PRINT("               ParsingRequest 5 error: %s", update_result.get_err_value().c_str());
            this->request_->set_status_code(NotFound);
            return Success;
        }
        this->request_->set_parse_phase(ParsingRequestBody);
    }

    if (this->request_->parse_phase() == ParsingRequestBody) {
        DEBUG_SERVER_PRINT("               ParsingRequest 6 body");
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_body();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.get_err_value();
            DEBUG_SERVER_PRINT("               ParsingRequest 7 body error: %d", error_code);
            this->request_->set_status_code(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 8 -> continue");
            return Continue;
        }
        DEBUG_SERVER_PRINT("               ParsingRequest 9");
    }
#endif
    return Success;
}


// -----------------------------------------------------------------------------


ProcResult ClientSession::create_http_response() {
    DEBUG_SERVER_PRINT("    CreatingResponse status: %d", this->request_->status_code());
    while (true) {
        switch (this->session_state_) {
            case kExecutingMethod: {
                DEBUG_SERVER_PRINT("     1 ExecutingMethod");
                ProcResult method_result = execute_each_method();  // todo: rename
                if (method_result == FatalError) {
                    return FatalError;
                }
                if (method_result == ExecutingCgi) {
                    return ExecutingCgi;
                }
            }
            // fallthrough

            case kCreatingResponseBody: {
                DEBUG_SERVER_PRINT("     2 CreatingResponseBody");
    #ifdef ECHO
                this->response_->create_echo_msg(this->request_->get_buf());
    #else
                this->response_->create_response_message();
    #endif
                this->set_session_state(kSendingResponse);
                break;
            }

            case kCreatingCGIBody: {
                DEBUG_SERVER_PRINT("     3 CreatingCGIBody");
                this->response_->interpret_cgi_output();
                this->set_session_state(kCreatingResponseBody);
                continue;
            }

            default:
                break;
        }
        break;
    }
    return Success;
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
    Result<AddressPortPair, std::string> address_result = get_address_port_pair();
    if (address_result.is_err()) {
        const std::string error_msg = address_result.get_err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    AddressPortPair address_port_pair = address_result.get_ok_value();
    // DEBUG_PRINT(YELLOW, "get_server_config");
    // DEBUG_PRINT(YELLOW, " address: %s, port:%s", address_port_pair.first.c_str(), address_port_pair.second.c_str());

    Result<HostPortPair, StatusCode> get_request_host = this->request_->server_info();
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

    const std::string request_target = this->request_->request_target();

    Result<std::size_t, int> body_size_result;
    body_size_result = Config::get_max_body_size(server_config_, request_target);
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


ProcResult ClientSession::execute_each_method() {
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
        return FatalError;
    }
    return this->response_->exec_method();  // return Success or ExecutingCgi
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
    switch (this->session_state_) {
        case kReadingFile: {
            // todo
            break;
        }

        case kExecutingCGI: {
            DEBUG_PRINT(YELLOW, "   FileEvent Recv");
            ProcResult cgi_result = this->response_->recv_to_cgi_buf();
            if (cgi_result == Continue) {
                DEBUG_PRINT(YELLOW, "    recv continue");
                return SessionResult::ok(Continue);
            }
            DEBUG_PRINT(YELLOW, "    recv finish");
            this->set_session_state(kCreatingCGIBody);
            break;
        }

        default: {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in file event");
            return SessionResult::err(error_msg);
        }
    }
    return SessionResult::ok(Success);
}


int ClientSession::cgi_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->cgi_fd();
}


int ClientSession::client_fd() const {
    return this->client_fd_;
}


SessionState ClientSession::session_state() const {
    return this->session_state_;
}

void ClientSession::set_session_state(const SessionState &set_state) {
    this->session_state_ = set_state;
}


bool ClientSession::is_session_state_expect(const SessionState &expect) const {
    return this->session_state_ == expect;
}


bool ClientSession::is_continue_recv(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == Continue;
}


bool ClientSession::is_continue_recv(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.get_ok_value() == Continue;
}


bool ClientSession::is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == PrepareNextProc;
}


bool ClientSession::is_executing_cgi(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.get_ok_value() == ExecutingCgi;
}


bool ClientSession::is_executing_cgi(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.get_ok_value() == ExecutingCgi;
}


bool ClientSession::is_connection_closed(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.get_ok_value() == ConnectionClosed;
}


AddressPortPair ClientSession::get_client_listen(const struct sockaddr_storage &client_addr) {
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
