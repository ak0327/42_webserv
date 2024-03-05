#include <sys/wait.h>
#include <sys/socket.h>
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
#include "Event.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "FileHandler.hpp"
#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "HttpMessageParser.hpp"
#include "Socket.hpp"
#include "StringHandler.hpp"


HttpResponse::HttpResponse(const HttpRequest &request,
                           const ServerConfig &server_config,
                           const AddressPortPair &server_listen,
                           const AddressPortPair &client_listen,
                           std::map<std::string, Session> *sessions,
                           time_t keepalive_timeout)
    : request_(request),
      server_config_(server_config),
      server_listen_(server_listen),
      client_listen_(client_listen),
      sessions_(sessions),
      cgi_handler_(),
      dynamic_(),
      status_code_(StatusOk),
      headers_(),
      body_buf_(),
      response_msg_(),
      keepalive_timeout_sec_(keepalive_timeout) {
    StatusCode request_status = this->request_.request_status();
    this->set_status_code(request_status);

    time_t cgi_timeout = Config::get_cgi_timeout(server_config, request.target());
    this->cgi_handler_.set_timeout_duration_sec(cgi_timeout);

    this->body_buf_ = this->request_.body();
}


HttpResponse::~HttpResponse() {}


bool HttpResponse::is_response_error_page() const {
    Result<std::string, int> result;
    result = Config::get_error_page(this->server_config_,
                                    this->request_.target(),
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


StatusCode HttpResponse::is_resource_available(const Method &method) const {
    // std::cout << CYAN << "is_resource_available target: " << this->request_.request_target() << RESET << std::endl;
    Result<std::string, StatusCode> indexed_result = Config::get_indexed_path(this->server_config_,
                                                                              this->request_.target());
    if (indexed_result.is_err()) {
        // std::cout << CYAN << " get_index failure: " << indexed_result.get_err_value() << RESET << std::endl;
        return indexed_result.err_value();
    }

    // std::cout << CYAN << " indexed_path: " << indexed_result.get_ok_value() << RESET << std::endl;

    Result<LimitExceptDirective, int> limit_except_result;
    limit_except_result = Config::limit_except(this->server_config_,
                                               this->request_.target());
    if (limit_except_result.is_err()) {
        // std::cout << CYAN << " not found" << RESET << std::endl;
        return NotFound;
    }

    LimitExceptDirective limit_except = limit_except_result.ok_value();
    if (limit_except.limited) {
        if (is_method_limited(method, limit_except.excluded_methods)) {
            // todo: allow, deny -> StatusOk
            // std::cout << CYAN << " method not allowed" << RESET << std::endl;
            return MethodNotAllowed;
        }
    }
    // std::cout << CYAN << " ok" << RESET << std::endl;
    return StatusOk;
}


void HttpResponse::add_allow_header() {
    Result<LimitExceptDirective, int> result = Config::limit_except(this->server_config_,
                                                                    this->request_.target());
    if (result.is_err()) {
        const std::string error_msg = CREATE_ERROR_INFO_STR("error: location not found");
        DEBUG_PRINT(RED, "%s", error_msg.c_str());  // todo: log
        return;
    }
    LimitExceptDirective limit_except = result.ok_value();
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

    StatusCode status;
    switch (this->request_.method()) {
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
    DEBUG_PRINT(YELLOW, " exec_method 8 -> next");
    return Success;
}


bool HttpResponse::is_status_error() const {
    int code_num = static_cast<int>(this->status_code());
    DEBUG_PRINT(MAGENTA, "is_status_error: %d %s"
                , code_num, (400 <= code_num && code_num <= 599 ? " true" : " false"));
    return 400 <= code_num && code_num <= 599;
}


ProcResult HttpResponse::send_http_response(int client_fd) {
    return Socket::send_buf(client_fd, &this->response_msg_);
}


std::string get_content_type(const std::string &type) {
    std::map<std::string, std::string>::const_iterator itr;
    itr = MIME_TYPES.find(type);
    if (itr != MIME_TYPES.end()) {
        return itr->second;
    }
    return "text/html";
}


void HttpResponse::add_content_header(const std::string &extension) {
    if (this->body_buf_.empty()) {
        return;
    }

    if (this->headers_.find("Content-Type") != this->headers_.end()) {
        // already added
        return;
    }

    std::string media_type = get_content_type(extension);
    return add_content_header_by_media_type(media_type);
}


void HttpResponse::add_content_header_by_media_type(const std::string &media_type) {
    if (this->body_buf_.empty()) {
        return;
    }

    if (media_type.empty()) {
        this->headers_["Content-Type"] = "text/html";
    } else {
        this->headers_["Content-Type"] = media_type;
    }
    this->headers_["Content-Length"] = StringHandler::to_string(this->body_buf_.size());
}



void HttpResponse::add_date_header() {
    this->headers_["Date"] = get_http_date();
}


void HttpResponse::add_server_header() {
    this->headers_["Server"] = std::string(SERVER_SEMANTIC_VERSION);
}


void HttpResponse::add_keepalive_header() {
    if (this->request_.is_client_connection_close() || this->keepalive_timeout_sec_ == 0) {
        this->headers_["Connection"] = "close";
    } else {
        this->headers_["Connection"] = "keep-alive";
        std::ostringstream field_value;
        field_value << "time=" << this->keepalive_timeout_sec_;
        this->headers_["Keep-Alive"] = field_value.str();
    }
}


void HttpResponse::add_standard_headers() {
    add_server_header();
    add_date_header();
    add_keepalive_header();
}

void HttpResponse::add_cookie_headers() {
    if (this->cookies_.empty()) {
        return;
    }

    std::map<std::string, std::string>::iterator cookie;
    for (cookie = this->cookies_.begin(); cookie != this->cookies_.end(); ++cookie) {
        std::ostringstream oss;
        oss << "Set-Cookie: " << cookie->first << "=" << cookie->second << CRLF;
        const std::string cookie_header = oss.str();
        this->response_msg_.insert(this->response_msg_.end(), cookie_header.begin(), cookie_header.end());
    }
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
    add_standard_headers();

    std::string status_line = create_status_line(this->status_code()) + CRLF;
    std::string field_lines = create_field_lines();
    std::string empty = CRLF;

    this->response_msg_.insert(this->response_msg_.end(), status_line.begin(), status_line.end());
    this->response_msg_.insert(this->response_msg_.end(), field_lines.begin(), field_lines.end());
    add_cookie_headers();
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
    status_line.append(1, SP);
    status_line.append(StringHandler::to_string(code));
    status_line.append(1, SP);
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


std::string HttpResponse::get_rooted_path() const {
    std::string root;
    Result<std::string, int> root_result = Config::get_root(this->server_config_,
                                                            this->request_.target());
    if (root_result.is_ok()) {
        root = root_result.ok_value();
    }

    std::string path = root + this->request_.target();
    return path;
}


ProcResult HttpResponse::send_request_body_to_cgi() {
    ProcResult result = this->cgi_handler_.send_request_body_to_cgi();
    if (result == Continue) {
        return Continue;
    }
    shutdown(this->cgi_write_fd(), SHUT_WR);
    DEBUG_PRINT(YELLOW, "shutdown cgi write_fd");
    if (result == Failure) {
        StatusCode error_code = InternalServerError;
        this->set_status_code(error_code);
    }
    return result;
}


ssize_t HttpResponse::recv_to_buf(int fd) {
    return Socket::recv_to_buf(fd, &this->body_buf_);
}


ProcResult HttpResponse::recv_to_cgi_buf() {
    ProcResult result = this->cgi_handler_.recv_cgi_output();
    if (result == Continue) {
        return Continue;
    }
    if (result == Failure) {
        StatusCode error_code = InternalServerError;
        this->set_status_code(error_code);
    }
    if (result == Timeout) {
        StatusCode error_code = GatewayTimeout;
        this->set_status_code(error_code);
    }
    return result;
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
    DEBUG_PRINT(GRAY, "response set_status [%d]->[%d]", this->status_code(), set_status);
    this->status_code_ = set_status;
}


int HttpResponse::cgi_read_fd() const {
    return this->cgi_handler_.read_fd();
}

int HttpResponse::cgi_write_fd() const {
    return this->cgi_handler_.write_fd();
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


void HttpResponse::create_echo_msg(const std::vector<unsigned char> &recv_msg) {
    this->response_msg_ = recv_msg;
    std::string echo_message = std::string(recv_msg.begin(), recv_msg.end());
    DEBUG_PRINT(GREEN, "    create_echo_msg:[%s]", echo_message.c_str());
}
