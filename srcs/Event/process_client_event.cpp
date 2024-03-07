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
#include "FileHandler.hpp"
#include "HttpResponse.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


// HttpRequest must memory allocate
// Using `new` in HttpRequest and copy ptr to HttpResponse
ProcResult Event::create_request_obj() {
    if (this->request_) {
        return Success;
    }

    try {
        this->request_ = new HttpRequest();
        return Success;
    }
    catch (const std::exception &e) {
        return FatalError;
    }
}

// status code update in this func if error occurred
EventResult Event::process_client_event() {
    // DEBUG_SERVER_PRINT("  client_event start (L:%d)", __LINE__);
    if (create_request_obj() == FatalError) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: fail to allocate memory for HttpRequest");
        return EventResult::err(error_msg);
    }

    switch (this->event_state_) {
        case kEventInit: {
            DEBUG_SERVER_PRINT("[process_client_event] Phase: 0 EventInit (L:%d)", __LINE__);
            this->set_event_phase(kReceivingRequest);
        }
        // fallthrough

        case kReceivingRequest: {
            DEBUG_SERVER_PRINT("[process_client_event] Phase: 1 ReceivingRequest (L:%d)", __LINE__);

            ssize_t recv_size = this->request_->recv_to_buf(this->client_fd_);
            if (recv_size == RECV_EOF) {  // 0  -> fd closed
                DEBUG_SERVER_PRINT(" recv EOF -> connection close (L:%d)", __LINE__);
                return EventResult::ok(ConnectionClosed);
            } else if (recv_size == RECV_CONTINUE) {    // -1 -> continue until timeout
                DEBUG_SERVER_PRINT(" recv -1 -> continue (L:%d)", __LINE__);
                return EventResult::ok(Continue);
            }
            this->set_event_phase(kParsingRequest);
        }
        // fallthrough

        case kParsingRequest: {
            DEBUG_SERVER_PRINT("[process_client_event] Phase: 2 ParsingRequest (L:%d)", __LINE__);
            ProcResult request_result = parse_http_request();
            if (request_result == Continue) {
                DEBUG_SERVER_PRINT("     recv continue(process_client_event) (L:%d)", __LINE__);
                this->set_event_phase(kReceivingRequest);
                return EventResult::ok(Continue);
            }
            this->set_event_phase(kExecutingMethod);
        }
        // fallthrough

        case kExecutingMethod:
        case kCreatingResponseBody:
        case kCreatingCGIBody: {
            DEBUG_SERVER_PRINT("[process_client_event] Phase: 3 CreatingResponse (L:%d)", __LINE__);
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
            DEBUG_SERVER_PRINT("[process_client_event] Phase: 4 SendingResponse (L:%d)", __LINE__);
            ProcResult send_result = this->response_->send_http_response(this->client_fd_);
            if (send_result == FatalError) {
                DEBUG_SERVER_PRINT(" send error -> close (L:%d)", __LINE__);
                return EventResult::ok(ConnectionClosed);
            }
            if (send_result == Continue) {
                DEBUG_SERVER_PRINT(" send -1 or size < buf.size() -> continue (L:%d)", __LINE__);
                return EventResult::ok(Continue);
            }
            // shutdown(this->client_fd_, SHUT_WR);
            DEBUG_SERVER_PRINT(" send complete -> success (L:%d)", __LINE__);
            this->set_event_phase(kEventCompleted);
            return EventResult::ok(Success);
        }

        default:
            const std::string error_msg = CREATE_ERROR_INFO_STR("error: unknown session in client event");
            return EventResult::err(error_msg);
    }
    DEBUG_SERVER_PRINT("  client_event end (L:%d)", __LINE__);
    return EventResult::ok(Success);
}

// -----------------------------------------------------------------------------

// status update this func
ProcResult Event::parse_http_request() {
    // DEBUG_SERVER_PRINT("               ParsingRequest start (L:%d)", __LINE__);
    if (this->echo_mode_on_) {
        this->set_event_phase(kCreatingResponseBody);
        return Success;
    }

    if (this->request_->parse_phase() == ParsingRequestLine
        || this->request_->parse_phase() == ParsingRequestHeaders) {
        // DEBUG_SERVER_PRINT("               ParsingRequest 1 (L:%d)", __LINE__);
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_start_line_and_headers();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.err_value();
            DEBUG_SERVER_PRINT(" ParsingRequest: error: %d", error_code);
            this->request_->set_request_status(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT(" ParsingRequest -> continue (L:%d)", __LINE__);
            return Continue;
        }

        if (this->request_->validate_request_headers() == FatalError) {
            this->request_->set_request_status(BadRequest);
            return Success;
        }

        // DEBUG_SERVER_PRINT("   ParsingRequest 4 (L:%d)", __LINE__);
        // todo: Result<ProcResult, StatusCode>
        Result<ProcResult, std::string> config_result = get_host_config();
        if (config_result.is_err()) {
            DEBUG_SERVER_PRINT(" ParsingRequest: error: %s", config_result.err_value().c_str());
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
        // DEBUG_SERVER_PRINT("               ParsingRequest 6 body (L:%d)", __LINE__);
        Result<ProcResult, StatusCode> parse_result = this->request_->parse_body();
        if (parse_result.is_err()) {
            StatusCode error_code = parse_result.err_value();
            DEBUG_SERVER_PRINT("  ParsingRequest: body error: %d", error_code);
            this->request_->set_request_status(error_code);
            return Success;
        }
        if (is_continue_recv(parse_result)) {
            DEBUG_SERVER_PRINT(" ParsingRequest -> continue (L:%d)", __LINE__);
            return Continue;
        }
        DEBUG_SERVER_PRINT(" ParsingRequest complete (L:%d)", __LINE__);
    }
    return Success;
}


// -----------------------------------------------------------------------------

ProcResult Event::create_response_obj() {
    if (this->response_) { return Success; }

    try {
        // unit test
        if (this->echo_mode_on_) {
            HttpRequest request; ServerConfig config; AddressPortPair pair;
            this->response_ = new HttpResponse(request, config, pair, pair, NULL, 0);
            this->set_event_phase(kCreatingResponseBody);
        } else {
            this->response_ = new HttpResponse(*this->request_,
                                               this->server_config_,
                                               this->server_listen_,
                                               this->client_listen_,
                                               this->sessions_,
                                               this->config_.keepalive_timeout());
            // std::cout << CYAN << "     response_message[" << this->http_response_->get_response_message() << "]" << RESET << std::endl;
        }
    }
    catch (const std::exception &e) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Failed to allocate memory");
        std::cerr << error_msg << std::endl;
        return FatalError;  // fail to new Request -> can't send 500
    }
    return Success;
}


// status changes in each func
ProcResult Event::create_http_response() {
    if (create_response_obj() == FatalError) {
        return FatalError;
    }

    DEBUG_SERVER_PRINT(" CreatingResponse status: %d", this->request_->request_status());
    while (true) {
        switch (this->event_state_) {
            case kExecutingMethod: {
                DEBUG_SERVER_PRINT(" [CreatingResponse] ExecutingMethod (L:%d)", __LINE__);
                ProcResult method_result = execute_each_method();  // todo: rename
                if (method_result == FatalError) {
                    DEBUG_SERVER_PRINT(" ExecutingMethod: err (L:%d)", __LINE__);
                    return FatalError;  // fail to new Request -> can't send 500
                }
                if (method_result == ExecutingCgi) {
                    DEBUG_SERVER_PRINT(" -> ExecutingCGI: send body to cgi proc (L:%d)", __LINE__);
                    return ExecutingCgi;
                }
                DEBUG_SERVER_PRINT(" -> create body (L:%d)", __LINE__);
            }
                // fallthrough

            case kCreatingResponseBody: {
                DEBUG_SERVER_PRINT("[CreatingResponse] CreatingResponseBody (L:%d)", __LINE__);
                if (this->echo_mode_on_) {
                    this->response_->create_echo_msg(this->request_->get_buf());
                } else {
                    this->response_->create_response_message();
                }

                this->set_event_phase(kSendingResponse);
                break;
            }

            case kCreatingCGIBody: {
                DEBUG_SERVER_PRINT(" [CreatingResponse] CreatingCGIBody (L:%d)", __LINE__);
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
    // DEBUG_PRINT(YELLOW, "get_server_config (L:%d)", __LINE__);
    // DEBUG_PRINT(YELLOW, " address: %s, port:%s", address_port_pair.first.c_str(), address_port_pair.second.c_str());

    Result<HostPortPair, StatusCode> get_request_host = this->request_->server_info();
    if (get_request_host.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("Fail to get host from Host header");
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    HostPortPair host_port_pair = get_request_host.ok_value();
    // DEBUG_PRINT(YELLOW, " host: %s, port:%s", host_port_pair.first.c_str(), host_port_pair.second.c_str());

    Result<ServerConfig, std::string> config_result;
    config_result = config_.get_server_config(this->server_listen_, host_port_pair);
    if (config_result.is_err()) {
        // DEBUG_PRINT(YELLOW, "get_server_config err (L:%d)", __LINE__);
        const std::string error_msg = config_result.err_value();
        return Result<ServerConfig, std::string>::err(error_msg);
    }
    // DEBUG_PRINT(YELLOW, "get_server_config ok (L:%d)", __LINE__);
    ServerConfig server_config = config_result.ok_value();
    return Result<ServerConfig, std::string>::ok(server_config);
}


EventResult Event::get_host_config() {
    Result<AddressPortPair, std::string> address_result = get_address_port_pair();
    if (address_result.is_err()) {
        const std::string error_msg = address_result.err_value();
        return EventResult::err(error_msg);
    }
    this->server_listen_ = address_result.ok_value();

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
        return Failure;
    }
    return ExecutingCgi;
}



bool HttpResponse::is_exec_cgi() {
    if (this->request_.method() != kGET && this->request_.method() != kPOST) {
        return false;
    }
    std::pair<ScriptPath, PathInfo> pair = get_script_path_and_path_info();
    std::string script_path = pair.first;
    Result<bool, StatusCode> result = FileHandler::is_file(script_path);
    return result.is_ok();
}


/*
 path/to/script.cgi/path/info
                    ^^^^^^^^^ PATH_INFO

  PATH_INFO = "" | ( "/" path )
  path      = lsegment *( "/" lsegment )
  lsegment  = *lchar
  lchar     = <any TEXT or CTL except "/">
  TEXT      = <any printable character>
  CTL       = <any control character>
  https://tex2e.github.io/rfc-translater/html/rfc3875.html#4-1-5--PATHINFO
 */
std::pair<ScriptPath, PathInfo> HttpResponse::get_script_path_and_path_info() {
    std::string target = this->request_.target();
    std::string script_path, path_info;

    DEBUG_PRINT(MAGENTA, "get script_path and path_info (L:%d)", __LINE__);
    std::size_t slash_pos = 0;
    while (slash_pos < target.length()) {
        slash_pos = target.find('/', slash_pos);
        if (slash_pos == std::string::npos) {
            break;
        }
        std::string tmp_script_path = target.substr(0, slash_pos);
        if (Config::is_cgi_extension(this->server_config_, tmp_script_path)) {
            script_path = tmp_script_path;
            path_info = target.substr(slash_pos + 1);
            break;
        }
        ++slash_pos;
    }

    if (script_path.empty() && Config::is_cgi_extension(this->server_config_, target)) {
        script_path = target;
    }

    std::string root;
    Result<std::string, int> root_result = Config::get_root(this->server_config_,
                                                            script_path);
    if (root_result.is_ok()) {
        root = root_result.ok_value();
        if (!root.empty() && root[root.length() - 1] == '/' && script_path[0] == '/') {
            script_path = script_path.substr(1);
        }
        script_path = root + script_path;
    }

    DEBUG_PRINT(MAGENTA, " script_path and path_info (L:%d)", __LINE__);
    DEBUG_PRINT(MAGENTA, "  script_path[%s]", script_path.c_str());
    DEBUG_PRINT(MAGENTA, "  path_info  [%s]", path_info.c_str());
    return std::make_pair(script_path, path_info);
}


CgiParams HttpResponse::get_cgi_params(const std::string &script_path,
                                       const std::string &path_info) {
    CgiParams params;

    if (this->request_.method() == kPOST) {
        params.content = this->request_.body();
        params.content_length = params.content.size();
        params.content_type = this->request_.content_type();
    }
    params.query_string = this->request_.query_string();
    params.path_info = path_info;
    params.script_path = script_path;

    DEBUG_PRINT(MAGENTA, "cgi params  (L:%d)", __LINE__);
    DEBUG_PRINT(MAGENTA, " content       : [%s]", std::string(params.content.begin(), params.content.end()).c_str());
    DEBUG_PRINT(MAGENTA, " content_length: [%zu]", params.content_length);
    DEBUG_PRINT(MAGENTA, " content_type  : [%s]", params.content_type.c_str());
    DEBUG_PRINT(MAGENTA, " query_string  : [%s]", params.query_string.c_str());
    DEBUG_PRINT(MAGENTA, " path_info     : [%s]", params.path_info.c_str());
    DEBUG_PRINT(MAGENTA, " script_path   : [%s]", params.script_path.c_str());

    return params;
}


ProcResult HttpResponse::exec_cgi_process() {
    std::pair<ScriptPath, PathInfo> pair = HttpResponse::get_script_path_and_path_info();

    CgiParams params = get_cgi_params(pair.first, pair.second);
    this->cgi_handler_.set_cgi_params(params);

    if (this->cgi_handler_.exec_script(params.script_path) == Failure) {
        this->set_status_code(InternalServerError);
        this->clear_cgi();
        return Failure;
    }
    return Success;
}


/*
 6.2.1. Document Response
 document-response = Content-Type [ Status ] *other-field NL response-body

 The script MUST return a Content-Type header field.
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-2-1--Document-Response

 Content-Type = "Content-Type:" media-type NL
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3-1--Content-Type

 Status         = "Status:" status-code SP reason-phrase NL
 status-code    = "200" | "302" | "400" | "501" | extension-code
 extension-code = 3digit
 reason-phrase  = *TEXT
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3-3--Status

 other-field     = protocol-field | extension-field
 protocol-field  = generic-field
 extension-field = generic-field
 generic-field   = field-name ":" [ field-value ] NL
 field-name      = token
 field-value     = *( field-content | LWSP )
 field-content   = *( token | separator | quoted-string )
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-3--Response-Header-Fields

 response-body = *OCTET
 https://tex2e.github.io/rfc-translater/html/rfc3875.html#6-4--Response-Message-Body

 UNIX
 The newline (NL) sequence is LF; servers should also accept CR LF as a newline.
                                          ^^^^^^
 */
void HttpResponse::interpret_cgi_output() {
    if (this->status_code() != StatusOk) {  // todo: cgi_status ??
        return;
    }

    StatusCode parse_status = this->cgi_handler_.parse_document_response();
    this->set_status_code(parse_status);

    if (is_status_error()) {
        return;
    }
    if (!is_supported_by_media_type(this->cgi_handler_.content_type())) {
        this->set_status_code(UnsupportedMediaType);
        return;
    }

    this->body_buf_ = this->cgi_handler_.cgi_body();
    add_content_header_by_media_type(this->cgi_handler_.content_type());
}
