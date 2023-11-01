#include "HttpResponse.hpp"

#include <iostream>
#include <sstream>

namespace {

const char HTTP_VERSION[] = "HTTP/1.1";
const char STATIC_ROOT[] = "www";

std::map<int, std::string> init_status_codes() {
	std::map<int, std::string> status_codes;

	status_codes[STATUS_OK] = "OK";

	status_codes[STATUS_NOT_FOUND] = "Not Found";
	status_codes[STATUS_NOT_ACCEPTABLE] = "Not Acceptable";

	return status_codes;
}

std::string decode(const std::string &target) {
	std::string decoded;
	(void)target;

	return decoded;
}

// "../" -> "/"
std::string canonicalize(const std::string &path) {
	std::string canonicalized;
	(void)path;

	return canonicalized;
}

std::string find_resource_path(const std::string &canonicalized_path,
							   const std::string &location) {
	const std::string PATH_DELIMITER = "/";

	// todo
	return location + PATH_DELIMITER + canonicalized_path;
}

// location:tmp
// '/' -> 'index.html'
std::string get_resource_path(const std::string &request_target,
							  const std::map<std::string, std::string> &locations) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string decoded_path;
	std::string canonicalized_path;
	std::string resource_path;
	std::string tmp_path;

	decoded_path = decode(request_target);
	canonicalized_path = canonicalize(decoded_path);

	// tmp
	if (request_target == "/") {
		resource_path = "/index.html";
	} else if (request_target[0] == '/') {
		resource_path = request_target;
	} else {
		resource_path = "/" + request_target;
	}
	return std::string(STATIC_ROOT) + resource_path;

	itr = locations.find(canonicalized_path);  // todo: tmp
	if (itr == locations.end()) {
		return std::string(STATIC_ROOT) + request_target;
	}
	resource_path = find_resource_path(canonicalized_path, itr->second);
	return resource_path;
}

enum e_method get_enum_method(const std::string &method) {
	if (method == "GET") {
		return GET;
	}
	if (method == "POST") {
		return POST;
	}
	if (method == "DELETE") {
		return DELETE;
	}
	return ERROR;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

HttpResponse::HttpResponse(const HttpRequest &request, const Config &config) {
	std::string			path;
	enum e_method		method;
	std::ostringstream	status_line_oss;

	_status_codes = init_status_codes();
	path = get_resource_path(request.get_request_target(),
							 config.get_locations());
	method = get_enum_method(request.get_method());

	//  request -> method -> status, header, body
	switch (method) {
		case GET:
			_status_code = get_request_body(request, config, path);
			break;
		case POST:
			_status_code = post_request_body();
			break;
		case DELETE:
			_status_code = delete_request_body();
			break;
		default:
			_status_code = STATUS_BAD_REQUEST;
			break;
	}
	status_line_oss << std::string(HTTP_VERSION)
					<< SP
					<< _status_code
					<< SP
					<< _status_codes[_status_code]
					<< CRLF;
	_status_line = status_line_oss.str();
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
	std::ostringstream response_headers_oss;
	std::string field_name, field_value;

	for (itr = _response_headers.begin(); itr != _response_headers.end(); ++itr) {
		field_name = itr->first;
		field_value = itr->second;

		response_headers_oss << field_name << ":" << SP << field_value << CRLF;
	}
	return response_headers_oss.str();
}

std::string HttpResponse::get_response_message() const {
	std::string response_message;

	response_message.append(_status_line);
	response_message.append(get_response_headers());
	response_message.append(CRLF);
	response_message.append(_response_body);
	return response_message;
}
