#include <iostream>
#include <sstream>
#include <vector>
#include "Color.hpp"
#include "HttpRequest.hpp"
#include "HttpResponse.hpp"
#include "HttpMessageParser.hpp"

namespace {

}  // namespace

////////////////////////////////////////////////////////////////////////////////

HttpResponse::HttpResponse(const HttpRequest &request) : request_(request) {}


HttpResponse::~HttpResponse() {}


Result<int, int> HttpResponse::exec_method() {
    std::string target = HttpResponse::get_resource_path(this->request_.get_request_target());
    Method method = HttpMessageParser::get_method(this->request_.get_method());
    std::ostringstream status_line_oss;

    switch (method) {
        case kGET:
            status_code_ = get_request_body(target);  // cgi -> return Fd
            break;

        case kPOST:
            status_code_ = post_request_body(target);  // cgi -> return Fd
            break;

        case kDELETE:
            status_code_ = delete_request_body(target);
            break;

        default:
            status_code_ = STATUS_BAD_REQUEST;
            return Result<int, int>::err(this->status_code_);
    }
    return Result<int, int>::ok(OK);
}


std::string HttpResponse::get_resource_path(const std::string &request_target) {
    std::string decoded = HttpMessageParser::decode(request_target);
    std::string normalized = HttpMessageParser::normalize(decoded);
    return normalized;
}


// field-line = field-name ":" OWS field-values OWS
std::string HttpResponse::get_field_lines() const {
	std::map<std::string, std::string>::const_iterator itr;
	std::ostringstream response_headers_oss;
	std::string field_name, field_value;

	for (itr = response_headers_.begin(); itr != response_headers_.end(); ++itr) {
		field_name = itr->first;
		field_value = itr->second;

		response_headers_oss << field_name << ":" << SP << field_value << CRLF;
	}
	return response_headers_oss.str();
}

/*
 HTTP-message = start-line CRLF
				*( field-line CRLF )
				CRLF
				[ message-body ]
 https://triple-underscore.github.io/http1-ja.html#http.message
 */
std::string HttpResponse::get_response_message() const {
    // this->response_message_.assign(this->status_line_.begin(), this->status_line_.end());

	std::string response_message;
	response_message.append(status_line_ + CRLF);
	response_message.append(get_field_lines());
	response_message.append(CRLF);
	// response_message.append(response_body_);
	return response_message;
}

#ifdef ECHO

void HttpResponse::create_echo_msg(const std::vector<unsigned char> &recv_msg) {
    this->echo_message_ = std::string(recv_msg.begin(), recv_msg.end());
    std::cout << MAGENTA << "echo msg:" << this->echo_message_ << RESET << std::endl;
}

std::string HttpResponse::get_echo_msg() const {
    return this->echo_message_;
}

#endif
