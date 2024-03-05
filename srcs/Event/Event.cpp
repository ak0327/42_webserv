#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <iostream>
#include <map>
#include <utility>
#include "Event.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


Event::Event(int socket_fd,
             int client_fd,
             const AddressPortPair &client_listen,
             const Config &config,
             std::map<std::string, Session> *sessions,
             bool echo_mode_on = false)
    : socket_fd_(socket_fd),
      client_fd_(client_fd),
      config_(config),
      server_info_(),
      server_config_(),
      event_state_(kEventInit),
      request_(NULL),
      response_(NULL),
      request_max_body_size_(ConfigInitValue::kDefaultBodySize),
      client_listen_(client_listen),
      sessions_(sessions),
      echo_mode_on_(echo_mode_on) {}


Event::~Event() {
    close_client_fd();
    clear_request();
    clear_response();
}


void Event::clear_request() {
    if (this->request_) {
        delete this->request_;
        this->request_ = NULL;
    }
}


void Event::clear_response() {
    if (this->response_) {
        delete this->response_;
        this->response_ = NULL;
    }
}


void Event::close_client_fd() {
    if (this->client_fd_ != INIT_FD) {
        close(this->client_fd_);
        this->client_fd_ = INIT_FD;
    }
}


void Event::kill_cgi_process() {
    if (this->response_) {
        this->response_->kill_cgi_process();
    }
}


// todo: unused??
void Event::clear_cgi() {
    if (this->response_) {
        this->response_->clear_cgi();
    }
}


time_t Event::cgi_timeout_limit() const {
    return this->response_ ? this->response_->cgi_timeout_limit() : 0;
}


// -----------------------------------------------------------------------------


// status code update in this func if error occurred
EventResult Event::process_client_event() {
    DEBUG_SERVER_PRINT("  client_event start");
    switch (this->event_state_) {
        case kEventInit: {
            DEBUG_SERVER_PRINT("   Session: 0 SessionInit");
            this->set_event_phase(kReceivingRequest);
        }
        // fallthrough

        case kReceivingRequest: {
            DEBUG_SERVER_PRINT("   Session: 1 Recv");
            ProcResult recv_result = recv_http_request();
            if (recv_result == FatalError) {
                const std::string error_msg = CREATE_ERROR_INFO_STR("error: fail to allocate memory for HttpRequest");
                return EventResult::err(error_msg);
            } else if (recv_result == Failure || recv_result == ConnectionClosed) {
                return EventResult::ok(ConnectionClosed);
            } else if (recv_result == Idling) {
                return EventResult::ok(Idling);
            } else if (recv_result == Continue) {
                return EventResult::ok(Continue);
            }
            this->set_event_phase(kParsingRequest);
        }
        // fallthrough

        case kParsingRequest: {
            DEBUG_SERVER_PRINT("   Session: 2 ParsingRequest");
            ProcResult request_result = parse_http_request();
            if (request_result == Continue) {
                DEBUG_SERVER_PRINT("     recv continue(process_client_event)");
                this->set_event_phase(kReceivingRequest);
                return EventResult::ok(Continue);
            }
            this->set_event_phase(kExecutingMethod);
        }
        // fallthrough

        case kExecutingMethod:
        case kCreatingResponseBody:
        case kCreatingCGIBody: {
            DEBUG_SERVER_PRINT("   Session: 3 CreatingResponse");
            ProcResult response_result = create_http_response();
            if (response_result == FatalError) {
                const std::string error_msg = CREATE_ERROR_INFO_STR("error: fail to allocate memory for HttpResponse");
                return EventResult::err(error_msg);
            }
            if (response_result == ExecutingCgi) {
                return EventResult::ok(ExecutingCgi);
            }
            break;
        }

        case kSendingResponse: {
            DEBUG_SERVER_PRINT("   Session: 4 SendingResponse");
            ProcResult send_result = this->response_->send_http_response(this->client_fd_);
            if (send_result == Failure) {
                return EventResult::ok(ConnectionClosed);
            }
            if (send_result == Continue) {
                return EventResult::ok(Continue);
            }
            this->set_event_phase(kEventCompleted);
            return EventResult::ok(Success);
        }

        default:
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in client event");
            return EventResult::err(error_msg);
    }
    DEBUG_SERVER_PRINT("  client_event end");
    return EventResult::ok(Success);
}


// -----------------------------------------------------------------------------


ProcResult Event::recv_http_request() {
    if (!this->request_) {
        try {
            this->request_ = new HttpRequest();
        }
        catch (const std::exception &e) {
            return FatalError;
        }
    }

    ssize_t recv_size = this->request_->recv_to_buf(this->client_fd_);
    if (recv_size == RECV_COMPLETED) {
        if (this->request_->is_buf_empty()) {
            return Idling;
        }
        return ConnectionClosed;
    }
    if (recv_size == RECV_ERROR) {
        return Failure;
    }
    return 0 < recv_size ? Success : Continue;
}


// -----------------------------------------------------------------------------

// status update this func
ProcResult Event::parse_http_request() {
    DEBUG_SERVER_PRINT("               ParsingRequest start");
    if (this->echo_mode_on_) {
        this->set_event_phase(kCreatingResponseBody);
        return Success;
    }

    if (this->request_->parse_phase() == ParsingRequestLine
        || this->request_->parse_phase() == ParsingRequestHeaders) {
        DEBUG_SERVER_PRINT("               ParsingRequest 1");
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_start_line_and_headers();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.err_value();
            DEBUG_SERVER_PRINT("               ParsingRequest 2 error: %d", error_code);
            this->request_->set_request_status(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 3 -> continue");
            return Continue;
        }

        if (this->request_->validate_request_headers() == FatalError) {
            this->request_->set_request_status(BadRequest);
            return Success;
        }

        DEBUG_SERVER_PRINT("               ParsingRequest 4");
        // todo: Result<ProcResult, StatusCode>
        Result<ProcResult, std::string> config_result = get_host_config();
        if (config_result.is_err()) {
            DEBUG_SERVER_PRINT("               ParsingRequest 5 error: %s", config_result.err_value().c_str());
            // StatusCode error_code = config_result.get_err_value();
            // DEBUG_SERVER_PRINT("               ParsingRequest 5 error: %d", error_code);
            this->request_->set_request_status(BadRequest);
            return Success;
        }

        // Result<ProcResult, StatusCode> content_length_result = this->request_->set_content_length();
        // if (content_length_result.is_err()) {
        //     StatusCode error_status = content_length_result.err_value();
        //     this->request_->set_request_status(error_status);
        //     return Success;
        // }
        this->request_->set_parse_phase(ParsingRequestBody);
    }

    if (this->request_->parse_phase() == ParsingRequestBody) {
        DEBUG_SERVER_PRINT("               ParsingRequest 6 body");
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_body();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.err_value();
            DEBUG_SERVER_PRINT("               ParsingRequest 7 body error: %d", error_code);
            this->request_->set_request_status(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT("               ParsingRequest 8 -> continue");
            return Continue;
        }
        DEBUG_SERVER_PRINT("               ParsingRequest 9");
    }
    return Success;
}


// -----------------------------------------------------------------------------


// status changes in each func
ProcResult Event::create_http_response() {
    DEBUG_SERVER_PRINT("    CreatingResponse status: %d", this->request_->request_status());
    while (true) {
        switch (this->event_state_) {
            case kExecutingMethod: {
                DEBUG_SERVER_PRINT("     1 ExecutingMethod");
                ProcResult method_result = execute_each_method();  // todo: rename
                if (method_result == FatalError) {
                    DEBUG_SERVER_PRINT("      ExecutingMethod 1 err");
                    return FatalError;  // fail to new Request -> can't send 500
                }
                if (method_result == ExecutingCgi) {
                    DEBUG_SERVER_PRINT("      ExecutingMethod 2 cgi -> send body to cgi");
                    return ExecutingCgi;
                }
                DEBUG_SERVER_PRINT("      ExecutingMethod 3 create body");
            }
            // fallthrough

            case kCreatingResponseBody: {
                DEBUG_SERVER_PRINT("     2 CreatingResponseBody");
                if (this->echo_mode_on_) {
                    this->response_->create_echo_msg(this->request_->get_buf());
                } else {
                    this->response_->create_response_message();
                }

                this->set_event_phase(kSendingResponse);
                break;
            }

            case kCreatingCGIBody: {
                DEBUG_SERVER_PRINT("     3 CreatingCGIBody");
                this->response_->interpret_cgi_output();
                this->set_event_phase(kCreatingResponseBody);
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


Result<AddressPortPair, std::string> Event::get_address_port_pair() const {
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


Result<ServerConfig, std::string> Event::get_server_config() const {
    // DEBUG_PRINT(YELLOW, "get_server_config");
    // DEBUG_PRINT(YELLOW, " address: %s, port:%s", address_port_pair.first.c_str(), address_port_pair.second.c_str());

    Result<HostPortPair, StatusCode> get_request_host = this->request_->server_info();
    if (get_request_host.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Fail to get host from Host header");
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    HostPortPair host_port_pair = get_request_host.ok_value();
    // DEBUG_PRINT(YELLOW, " host: %s, port:%s", host_port_pair.first.c_str(), host_port_pair.second.c_str());

    Result<ServerConfig, std::string> config_result;
    config_result = config_.get_server_config(this->address_port_pair_, host_port_pair);
    if (config_result.is_err()) {
        // DEBUG_PRINT(YELLOW, "get_server_config err");
        const std::string error_msg = config_result.err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    // DEBUG_PRINT(YELLOW, "get_server_config ok");
    ServerConfig server_config = config_result.ok_value();
    return Result<ServerConfig, std::string>::ok(server_config);
}


EventResult Event::get_host_config() {
    Result<AddressPortPair, std::string> address_result = get_address_port_pair();
    if (address_result.is_err()) {
        const std::string error_msg = address_result.err_value();
        return EventResult::err(error_msg);
    }
    this->address_port_pair_ = address_result.ok_value();

    Result<ServerConfig, std::string> config_result = Event::get_server_config();
    if (config_result.is_err()) {
        const std::string error_msg = config_result.err_value();
        return EventResult::err(error_msg);
    }
    this->server_config_ = config_result.ok_value();

    const std::string request_target = this->request_->target();

    Result<std::size_t, int> body_size_result;
    body_size_result = Config::get_max_body_size(server_config_, request_target);
    if (body_size_result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: fail to get client_max_body_size");
        return EventResult::err(error_msg);
    }
    std::size_t max_body_size = body_size_result.ok_value();
    this->request_->set_max_body_size(max_body_size);
    return EventResult::ok(Success);
}


// -----------------------------------------------------------------------------


ProcResult Event::execute_each_method() {
    if (this->echo_mode_on_) {
        try {
            HttpRequest request; ServerConfig config; AddressPortPair pair;
            this->response_ = new HttpResponse(request, config, pair, NULL, 0);
        }
        catch (const std::exception &e) {
            const std::string error_msg = CREATE_ERROR_INFO_STR("Failed to allocate memory");
            std::cerr << error_msg << std::endl;
            return FatalError;
        }
        return Success;
    }

    try {
        this->response_ = new HttpResponse(*this->request_,
                                           this->server_config_,
                                           this->address_port_pair_,
                                           this->sessions_,
                                           this->config_.keepalive_timeout());
        // std::cout << CYAN << "     response_message[" << this->http_response_->get_response_message() << "]" << RESET << std::endl;
    }
    catch (const std::exception &e) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << error_msg << std::endl;
        return FatalError;  // fail to new Request -> can't send 500
    }
    if (this->response_->is_exec_cgi()) {
        return exec_cgi();
    } else {
        return this->response_->exec_method();  // return Success or ExecutingCgi
    }
}


ProcResult Event::exec_cgi() {
    this->set_event_phase(kExecuteCGI);
    EventResult result = process_file_event();
    if (result.is_err()) {
        std::cerr << result.err_value() << std::endl;  // todo: logging
        return Failure;  // todo: 500
    }
    return ExecutingCgi;
}


EventResult Event::process_file_event() {
    switch (this->event_state_) {
        case kReadingFile: {
            // unused
            break;
        }

        // call from process_client_event
        case kExecuteCGI: {
            DEBUG_PRINT(YELLOW, "   CGI Executing");
            ProcResult exec_result = this->response_->exec_cgi_process();
            if (exec_result == Failure) {
                const std::string error_msg = CREATE_ERROR_INFO_STR("cgi exec error");
                return EventResult::err(error_msg);
            }
            DEBUG_PRINT(YELLOW, "    success -> send");
            this->set_event_phase(kSendingRequestBodyToCgi);
            return EventResult::ok(ExecutingCgi);
            // todo register write fd
        }

        case kSendingRequestBodyToCgi: {
            DEBUG_PRINT(YELLOW, "   CGI Send");
            ProcResult send_result = this->response_->send_request_body_to_cgi();
            if (send_result == Continue) {
                DEBUG_PRINT(YELLOW, "    send continue");
                return EventResult::ok(Continue);
            }
            if (send_result == Success) {
                DEBUG_PRINT(YELLOW, "    send finish");
                this->set_event_phase(kReceivingCgiResponse);
            } else {
                // error -> response 500
                DEBUG_PRINT(YELLOW, "    send error");
                // this->set_session_state(kCreatingResponseBody);
                this->set_event_phase(kCreatingCGIBody);
            }
            break;
        }

        case kReceivingCgiResponse: {
            DEBUG_PRINT(YELLOW, "   CGI Recv");
            ProcResult recv_result = this->response_->recv_to_cgi_buf();
            if (recv_result == Continue) {
                DEBUG_PRINT(YELLOW, "    recv continue");
                return EventResult::ok(Continue);
            }
            if (recv_result == Success) {
                DEBUG_PRINT(YELLOW, "    recv finish");
                this->set_event_phase(kCreatingCGIBody);
            } else {
                DEBUG_PRINT(YELLOW, "    recv error");
                // error -> response 500
                // this->set_session_state(kCreatingResponseBody);
                this->set_event_phase(kCreatingCGIBody);
            }
            break;
        }

        default: {
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in file event");
            return EventResult::err(error_msg);
        }
    }
    return EventResult::ok(Success);
}


int Event::cgi_read_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->cgi_read_fd();
}


int Event::cgi_write_fd() const {
    if (!this->response_) {
        return INIT_FD;
    }
    return this->response_->cgi_write_fd();
}


int Event::client_fd() const {
    return this->client_fd_;
}


EventPhase Event::event_phase() const {
    return this->event_state_;
}


std::string Event::event_phase_str(const EventPhase &phase) {
    return std::string(event_phase_char(phase));
}


const char *Event::event_phase_char() {
    return event_phase_char(this->event_phase());
}


const char *Event::event_phase_char(const EventPhase &phase) {
    switch (phase) {
        case kEventInit:                return "kEventInit";
        case kReceivingRequest:         return "kReceivingRequest";
        case kParsingRequest:           return "kParsingRequest";
        case kReceivingBody:            return "kReceivingBody";
        case kReadingRequest:           return "kReadingRequest";
        case kExecutingMethod:          return "kExecutingMethod";
        case kCreatingResponseBody:     return "kCreatingResponseBody";
        case kCreatingCGIBody:          return "kCreatingCGIBody";
        case kReadingFile:              return "kReadingFile";
        case kExecuteCGI:               return "kExecuteCGI";
        case kSendingRequestBodyToCgi:  return "kSendingRequestBodyToCgi";
        case kReceivingCgiResponse:     return "kReceivingCgiResponse";
        case kSendingResponse:          return "kSendingResponse";
        case kEventCompleted:           return "kEventCompleted";
        case kEventError:               return "kEventError";
        default:                        return "UnknownEvent";
    }
}



void Event::set_event_phase(const EventPhase &set_phase) {
    DEBUG_PRINT(WHITE, "set_event_phase [%s]->[%s]",
                event_phase_char(this->event_state_),
                event_phase_char(set_phase));
    this->event_state_ = set_phase;
}


bool Event::is_event_phase_expect(const EventPhase &expect) const {
    return this->event_state_ == expect;
}


bool Event::is_continue_recv(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == Continue;
}


bool Event::is_continue_recv(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == Continue;
}


bool Event::is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == PrepareNextProc;
}


bool Event::is_executing_cgi(const Result<ProcResult, StatusCode> &result) {
    return result.is_ok() && result.ok_value() == ExecutingCgi;
}


bool Event::is_executing_cgi(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == ExecutingCgi;
}


bool Event::is_connection_closed(const Result<ProcResult, std::string> &result) {
    return result.is_ok() && result.ok_value() == ConnectionClosed;
}


bool Event::is_keepalive() const {
    if (!this->request_ || this->request_->is_client_connection_close()) {
        return false;
    }
    return this->config_.keepalive_timeout() != 0;
}


AddressPortPair Event::get_client_listen(const struct sockaddr_storage &client_addr) {
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

std::ostringstream &operator<<(std::ostringstream &out, const Event &event) {
    out << "[Event]: ";
    out << "phase: " << Event::event_phase_str(event.event_phase()) << ", ";
    out << "client_fd: " << event.client_fd() << ", ";
    out << "cgi_read_fd: " << event.cgi_read_fd() << ", ";
    out << "cgi_write_fd: " << event.cgi_write_fd();
    return out;
}
