#include <iostream>
#include <sstream>

#include "Color.hpp"
#include "HttpResponse.hpp"

namespace {

const char HTTP_VERSION[] = "HTTP/1.1";
const char STATIC_ROOT[] = "www";

std::map<int, std::string> init_status_reason_phrase() {
	std::map<int, std::string> status_reason_phrase;

	status_reason_phrase[STATUS_OK] = "OK";
	status_reason_phrase[STATUS_BAD_REQUEST] = "Bad Request";
	status_reason_phrase[STATUS_NOT_FOUND] = "Not Found";
	status_reason_phrase[STATUS_NOT_ACCEPTABLE] = "Not Acceptable";

	return status_reason_phrase;
}

std::map<int, std::string> init_error_pages() {
	std::map<int, std::string> error_pages;

	error_pages[STATUS_BAD_REQUEST] = std::string(error_400_page);

	error_pages[STATUS_NOT_FOUND] = std::string(error_404_page);
	error_pages[STATUS_NOT_ACCEPTABLE] = std::string(error_406_page);

	error_pages[STATUS_SERVER_ERROR] = std::string(error_500_page);

	return error_pages;
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

bool get_autoindex(const std::string &request_target, const Config &config) {
	(void)request_target;

	return config.get_autoindex();
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

HttpResponse::HttpResponse(const HttpRequest &request, const Config &config) {
	std::string			path;
	enum e_method		method;
	bool				autoindex;
	std::ostringstream	status_line_oss;

	_status_reason_phrase = init_status_reason_phrase();
	_error_pages = init_error_pages();

	path = get_resource_path(request.get_request_target(),
							 config.get_locations());
	autoindex = get_autoindex(request.get_request_target(), config);
	method = get_enum_method(request.get_method());

	//  request -> method -> status, header, body
	switch (method) {
		case GET:
			_status_code = get_request_body(request, config, path, autoindex);
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

	// status-line = HTTP-version SP status-code SP [ reason-phrase ]
	status_line_oss << std::string(HTTP_VERSION)
					<< SP
					<< _status_code
					<< SP
					<< _status_reason_phrase[_status_code];
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

// field-line = field-name ":" OWS field-values OWS
std::string HttpResponse::get_field_lines() const {
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

/*
 HTTP-message = start-line CRLF
				*( field-line CRLF )
				CRLF
				[ message-body ]
 https://triple-underscore.github.io/http1-ja.html#http.message
 */
std::string HttpResponse::get_response_message() const {
	std::string response_message;

	response_message.append(_status_line + CRLF);
	response_message.append(get_field_lines());
	response_message.append(CRLF);
	response_message.append(_response_body);
	return response_message;
}
