#include "HttpResponse.hpp"

#include <iostream>
#include <sstream>

namespace {
	const std::string HTTP_VERSION = "HTTP/1.1";

	std::map<int, std::string> init_status_codes() {
		std::map<int, std::string> status_codes;

		status_codes[200] = "OK";

		status_codes[404] = "Not Found";
		status_codes[406] = "Not Acceptable";

		return status_codes;
	}
}  // namespace

HttpResponse::HttpResponse(const HttpRequest &request, const Configuration &config) {
	_status_codes = init_status_codes();

	//  todo
	//  request -> method -> status, header, body
	switch (request.get_method()) {
		case GET:
			_status_code = get_request_body(request, config);
			break;
		case POST:
			_status_code = post_request_body();
			break;
		case DELETE:
			_status_code = delete_request_body();
			break;
		default:
			_status_code = 400;  	// tmp
			break;
	}
	std::ostringstream oss;
	oss << HTTP_VERSION << SP << _status_code << SP << _status_codes[_status_code];
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

std::string HttpResponse::get_response_headers() const {
	std::map<std::string, std::string>::const_iterator itr;
	std::ostringstream oss;

	for (itr = _response_headers.begin(); itr != _response_headers.end(); ++itr) {
		oss << itr->first << ":" << SP << itr->second << CRLF;
	}
	return oss.str();
}


std::string HttpResponse::get_response_message() const {
	std::string response_message;

	response_message += _status_line;
	response_message += get_response_headers();
	response_message += CRLF;
	response_message += _response_body;
	return response_message;
}
