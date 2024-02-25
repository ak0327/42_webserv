#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <vector>
#include "webserv.hpp"
#include "Color.hpp"
#include "Config.hpp"
#include "ClientSession.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

namespace {

}  // namespace

////////////////////////////////////////////////////////////////////////////////

HttpResponse::HttpResponse(const HttpRequest &request,
                           const ServerConfig &server_config,
                           const AddressPortPair &pair)
    : request_(request),
      server_config_(server_config),
      address_port_pair_(pair),
      cgi_handler_(),
      headers_(),
      body_buf_(),
      response_msg_() {
    StatusCode request_status = this->request_.status_code();
    this->set_status_code(request_status);

    time_t cgi_timeout = Config::get_cgi_timeout(server_config, request.request_target());
    this->cgi_handler_.set_timeout_duration_sec(cgi_timeout);

    this->body_buf_ = this->request_.body();
}


HttpResponse::~HttpResponse() {}


bool HttpResponse::is_response_error_page() const {
    Result<std::string, int> result;
    result = Config::get_error_page(this->server_config_,
                                    this->request_.request_target(),
                                    this->status_code());
    return result.is_ok();
}


bool HttpResponse::is_executing_cgi() const {
    return this->cgi_handler_.is_processing();
}


bool is_method_limited(const Method &method, const std::set<Method> &excluded_methods) {
    std::set<Method>::const_iterator itr = excluded_methods.find(method);
    return itr == excluded_methods.end();
}


StatusCode HttpResponse::check_resource_availability(const Method &method) const {
    Result<LimitExceptDirective, int> limit_except_result;
    limit_except_result = Config::limit_except(this->server_config_,
                                               this->request_.request_target());
    if (limit_except_result.is_err()) {
        return NotFound;
    }

    LimitExceptDirective limit_except = limit_except_result.get_ok_value();
    if (limit_except.limited) {
        if (is_method_limited(method, limit_except.excluded_methods)) {
            // todo: allow, deny -> StatusOk
            return MethodNotAllowed;
        }
    }
    return StatusOk;
}


void HttpResponse::add_allow_header() {
    Result<LimitExceptDirective, int> result = Config::limit_except(this->server_config_,
                                                                    this->request_.request_target());
    if (result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: location not found");
        DEBUG_PRINT(RED, "%s", error_msg.c_str());  // todo: log
        return;
    }
    LimitExceptDirective limit_except = result.get_ok_value();
    std::set<Method> &excluded_methods = limit_except.excluded_methods;
    if (excluded_methods.empty()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: excluded method not found");
        DEBUG_PRINT(RED, "%s", error_msg.c_str());  // todo: log
        return;
    }

    std::string allowed_method;
    std::set<Method>::const_iterator method;
    for (method = excluded_methods.begin(); method != excluded_methods.end(); ++method) {
        if (!allowed_method.empty()) {
            allowed_method.append(", ");
        }
        std::string method_str = HttpMessageParser::convert_to_str(*method);
        allowed_method.append(method_str);
    }
    this->headers_["Allow"] = allowed_method;
}


void HttpResponse::process_method_not_allowed() {
    add_allow_header();
    this->set_status_code(MethodNotAllowed);
}


ProcResult HttpResponse::exec_method() {
    DEBUG_PRINT(YELLOW, " exec_method 1 status(%d)", this->status_code());
    if (is_status_error()) {
        DEBUG_PRINT(YELLOW, " exec_method 2 -> error_page");
        return Success;
    }
    Method method = HttpMessageParser::get_method(this->request_.method());

    StatusCode availability = check_resource_availability(method);
    DEBUG_PRINT(YELLOW, "  check_resource_availablity -> %d", availability);
    if (availability != StatusOk) {
        if (availability == MethodNotAllowed) {
            add_allow_header();
        }
        this->set_status_code(availability);
        DEBUG_PRINT(YELLOW, " exec_method 3 -> error %d", availability);
        return Success;
    }


    StatusCode status;
    switch (method) {
        case kGET:
            DEBUG_PRINT(YELLOW, " exec_method 5 - GET");
            status = get_request_body();
            break;

        case kPOST:
            DEBUG_PRINT(YELLOW, " exec_method 5 - POST");
            status = post_target();
            break;

        case kDELETE:
            DEBUG_PRINT(YELLOW, " exec_method 5 - DELETE");
            status = delete_target();
            break;

        default:
            DEBUG_PRINT(YELLOW, " exec_method 5 - method err");
            status = BadRequest;
    }

    this->set_status_code(status);
    DEBUG_PRINT(YELLOW, " exec_method 6 status: %d", this->status_code());
    if (is_executing_cgi()) {
        DEBUG_PRINT(YELLOW, " exec_method 7 executing cgi -> continue");
        return ExecutingCgi;
    }

    DEBUG_PRINT(YELLOW, " exec_method 8 -> next");
    return Success;
}


bool HttpResponse::is_status_error() const {
    int code_num = static_cast<int>(this->status_code());
    std::cout << MAGENTA << "is_status_error: " << code_num
              << (400 <= code_num && code_num <= 599 ? " true" : " false")
              << RESET << std::endl;
    return 400 <= code_num && code_num <= 599;
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
ProcResult HttpResponse::interpret_cgi_output() {
    StatusCode parse_status = this->cgi_handler_.parse_document_response();
    this->set_status_code(parse_status);

    if (!is_status_error()) {
        this->body_buf_ = this->cgi_handler_.cgi_body();
    }
    return Success;
}


/*
 HTTP-message = start-line CRLF
				*( field-line CRLF )
				CRLF
				[ message-body ]
 https://triple-underscore.github.io/http1-ja.html#http.message
 */
void HttpResponse::create_response_message() {
    if (is_status_error()) {
        this->body_buf_.clear();
    }
    if (is_response_error_page()) {
        DEBUG_PRINT(YELLOW, " exec_method 2 -> error_page", this->status_code());
        get_error_page_to_body();
    }

    std::string status_line = create_status_line(this->status_code()) + CRLF;
    std::string field_lines = create_field_lines();
    std::string empty = CRLF;

    this->response_msg_.insert(this->response_msg_.end(), status_line.begin(), status_line.end());
    this->response_msg_.insert(this->response_msg_.end(), field_lines.begin(), field_lines.end());
    this->response_msg_.insert(this->response_msg_.end(), empty.begin(), empty.end());
    this->response_msg_.insert(this->response_msg_.end(), this->body_buf_.begin(), this->body_buf_.end());

    std::string msg(this->response_msg_.begin(), this->response_msg_.end());
    DEBUG_SERVER_PRINT("response_message2:[%s]", msg.c_str());
}


std::string get_status_reason_phrase(const StatusCode &code) {
    std::map<StatusCode, std::string>::const_iterator itr;
    itr = STATUS_REASON_PHRASES.find(code);
    if (itr == STATUS_REASON_PHRASES.end()) {
        return EMPTY;
    }
    return itr->second;
}


// status-line = HTTP-version SP status-code SP [ reason-phrase ]
std::string HttpResponse::create_status_line(const StatusCode &code) const {
    std::string status_line;

    status_line.append(this->request_.http_version());
    status_line.append(SP);
    status_line.append(StringHandler::to_string(code));
    status_line.append(SP);
    status_line.append(get_status_reason_phrase(code));
    return status_line;
}


// field-line = field-name ":" OWS field-values OWS
std::string HttpResponse::create_field_lines() const {
	std::map<std::string, std::string>::const_iterator itr;
	std::ostringstream response_headers_oss;
	std::string field_name, field_value;

	for (itr = headers_.begin(); itr != headers_.end(); ++itr) {
		field_name = itr->first;
		field_value = itr->second;

		response_headers_oss << field_name << ":" << SP << field_value << CRLF;
	}
	return response_headers_oss.str();
}


std::string HttpResponse::get_resource_path() {
    std::string root;
    Result<std::string, int> root_result = Config::get_root(this->server_config_,
                                                            this->request_.request_target());
    if (root_result.is_ok()) {
        root = root_result.get_ok_value();
    }

    std::string path = root + this->request_.request_target();
    return path;
}


ssize_t HttpResponse::recv_to_buf(int fd) {
    return HttpRequest::recv_to_buf(fd, &this->body_buf_);
}


ProcResult HttpResponse::recv_to_cgi_buf() {
    Result<ProcResult, StatusCode> result = this->cgi_handler_.recv_cgi_output();
    if (result.is_err()) {
        StatusCode error_code = result.get_err_value();
        this->set_status_code(error_code);
    }
    if (ClientSession::is_continue_recv(result)) {
        return Continue;
    }
    return Success;
}


const std::vector<unsigned char> &HttpResponse::body_buf() const {
    return this->body_buf_;
}


const std::vector<unsigned char> &HttpResponse::get_response_message() const {
    return this->response_msg_;
}


StatusCode HttpResponse::status_code() const {
    return this->status_code_;
}


void HttpResponse::set_status_code(const StatusCode &set_status) {
    this->status_code_ = set_status;
}


int HttpResponse::cgi_fd() const {
    return this->cgi_handler_.fd();
}


time_t HttpResponse::cgi_timeout_limit() const {
    return this->cgi_handler_.timeout_limit();
}


void HttpResponse::kill_cgi_process() {
    this->cgi_handler_.kill_cgi_process();
}


// todo: unused??
void HttpResponse::clear_cgi() {
    this->cgi_handler_.clear_cgi_process();
}


#ifdef ECHO

void HttpResponse::create_echo_msg(const std::vector<unsigned char> &recv_msg) {
    this->response_msg_ = recv_msg;
    std::string echo_message = std::string(recv_msg.begin(), recv_msg.end());
    DEBUG_PRINT(GREEN, "    create_echo_msg:[%s]", echo_message.c_str());
}

#endif
