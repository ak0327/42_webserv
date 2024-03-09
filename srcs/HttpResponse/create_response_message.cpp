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
        // DEBUG_PRINT(YELLOW, " exec_method 2 -> error_page", this->status_code());
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
    DEBUG_SERVER_PRINT("response_message:[%s]", msg.c_str());
}


bool HttpResponse::is_status_error() const {
    if (is_status_client_error(this->status_code())) {
        DEBUG_PRINT(MAGENTA, "is_status_error: %d: client error");
        return true;
    }
    if (is_status_server_error(this->status_code())) {
        DEBUG_PRINT(MAGENTA, "is_status_error: %d: server error");
        return true;
    }
    return false;
}


bool HttpResponse::is_successful_status(StatusCode code) {
    int code_num = static_cast<int>(code);
    return 200 <= code_num && code_num <= 299;
}


bool HttpResponse::is_redirection_status(StatusCode code) {
    int code_num = static_cast<int>(code);
    return 300 <= code_num && code_num <= 399;
}


bool HttpResponse::is_status_client_error(StatusCode code) {
    int code_num = static_cast<int>(code);
    return 400 <= code_num && code_num <= 499;
}


bool HttpResponse::is_status_server_error(StatusCode code) {
    int code_num = static_cast<int>(code);
    return 500 <= code_num && code_num <= 599;
}



bool HttpResponse::is_response_error_page() const {
    Result<std::string, int> result;
    result = Config::get_error_page(this->server_config_,
                                    this->request_.target(),
                                    this->status_code());
    return result.is_ok();
}


void HttpResponse::get_error_page_to_body() {
    this->body_buf_.clear();

    // get_error_page_path
    // DEBUG_PRINT(CYAN, "  get_error_page 1 target: %s, request_status: %d",
    //             this->request_.target().c_str(), this->status_code());
    Result<std::string, int> result;
    result = Config::get_error_page_path(this->server_config_,
                                         this->request_.target(),
                                         this->status_code());
    if (result.is_err()) {
        // DEBUG_PRINT(CYAN, "  get_error_page 2 -> err");
        return;
    }
    // DEBUG_PRINT(CYAN, "  get_error_page 3");
    std::string error_page_path = result.ok_value();
    // DEBUG_PRINT(CYAN, "  get_error_page 4 error_page_path: %s", error_page_path.c_str());
    get_file_content(error_page_path, &this->body_buf_);
}


void HttpResponse::add_standard_headers() {
    add_server_header();
    add_date_header();
    add_keepalive_header();
    add_content_length();
    add_allow_header();
}


void HttpResponse::add_date_header() {
    this->headers_["Date"] = get_http_date();
}


void HttpResponse::add_server_header() {
    this->headers_["Server"] = std::string(SERVER_SEMANTIC_VERSION);
}


bool HttpResponse::is_request_too_large() const {
    return this->status_code() == PayloadTooLarge
            || this->status_code() == RequestHeaderFieldsTooLarge
            || this->request_.request_line_status() == StatusInit;  // too long error
}


bool HttpResponse::is_keepalive() const {
    if (this->request_.is_client_connection_close()) {
        return false;
    }
    const int KEEPALIVE_TIMEOUT_INFINITY = 0;
    if (this->keepalive_timeout_sec_ == KEEPALIVE_TIMEOUT_INFINITY) {
        return false;
    }
    if (is_request_too_large()) {
        return false;
    }
    return true;
}


void HttpResponse::add_keepalive_header() {
    if (is_keepalive()) {
        this->headers_["Connection"] = "keep-alive";
        std::ostringstream field_value;
        field_value << "time=" << this->keepalive_timeout_sec_;
        field_value << ", max=" << MAX_CONNECTION;
        this->headers_["Keep-Alive"] = field_value.str();
    } else {
        this->headers_["Connection"] = "close";
    }
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
    // this->headers_["Content-Length"] = StringHandler::to_string(this->body_buf_.size());
}


void HttpResponse::add_allow_header() {
    if (this->status_code() != MethodNotAllowed) {
        return;
    }

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



void HttpResponse::add_content_length() {
    this->headers_["Content-Length"] = StringHandler::to_string(this->body_buf_.size());
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

    status_line.append(std::string(HTTP_1_1));
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
