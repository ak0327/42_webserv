#include "HttpResponse.hpp"

#include <iostream>
#include <sstream>

HttpResponse::HttpResponse(const HttpRequest &request) {
	//  todo
	//  request -> method -> status, header, body
	switch (request.get_method()) {
		case GET:
			_status_code = get_request_body();
			break;
		case POST:
			_status_code = post_request_body();
			break;
		case DELETE:
			_status_code = delete_request_body();
			break;
		default:
			_status_code = 400;  	// tmp
			_response_header = "";  // tmp
			break;
	}
	std::ostringstream oss;
	oss << "HTTP/1.1" << SP << _status_code << SP << "OK";
	_status_line = oss.str();
}

HttpResponse::HttpResponse(const HttpResponse &other) {
	(void)other;
	//  todo
}

HttpResponse::~HttpResponse() {
	//  todo
}

HttpResponse &HttpResponse::operator=(const HttpResponse &rhs) {
	if (this == &rhs) {
		return *this;
	}
	//  todo
	return *this;
}

std::string HttpResponse::get_response_message() const {
	std::string response_message;

	response_message += _status_line;
	response_message += _response_header;
	response_message += CRLF;
	response_message += _response_body;
	return response_message;
}
