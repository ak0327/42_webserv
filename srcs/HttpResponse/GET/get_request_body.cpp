#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include "Color.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

namespace {

const char EXTENSION_DOT = '.';

// tmp -----------------------------
// const char PATH_ROOT[] = "/";
// const char PATH_INDEX[] = "index.html";
const char STATIC_ROOT[] = "www";
const char NOT_FOUND_PATH[] = "www/404.html";
// ---------------------------------

const char EMPTY_STR[] = "";

const std::size_t INIT_CONTENT_LENGTH = 0;

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

std::string get_extension(const std::string &path) {
	std::size_t ext_pos;

	ext_pos = path.find_last_of(EXTENSION_DOT);
	if (ext_pos == std::string::npos) {
		return std::string(EMPTY_STR);
	}
	return path.substr(ext_pos + 1);
}

bool is_support_content_type(const std::string &path,
							 const std::map<std::string, std::string> &mime_types) {
	std::string extension;
	std::map<std::string, std::string>::const_iterator itr;

	extension = get_extension(path);
	itr = mime_types.find(extension);
	return itr != mime_types.end();
}

// todo: int, double,...
std::string to_str(std::size_t num) {
	std::ostringstream oss;

	oss << num;
	return oss.str();
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

// todo: mv lib
/* return file content and content_length */
Result<std::string, int> get_file_content(const std::string &file_path,
										  std::size_t *ret_content_length) {
	std::ifstream	ifs;
	std::string		content;
	std::string		buf;
	std::size_t		content_length;

	if (ret_content_length) {
		*ret_content_length = INIT_CONTENT_LENGTH;
	}

	ifs.open(file_path.c_str(), std::ios::in);
	if (ifs.fail()) {
		return Result<std::string, int>::err(STATUS_NOT_FOUND);
	}

	content_length = INIT_CONTENT_LENGTH;
	content = EMPTY_STR;
	while (std::getline(ifs, buf)) {
		content.append(buf + (ifs.eof() ? "" : "\n"));
		content_length += buf.length() + (ifs.eof() ? 0 : 1);
	}
	if (ret_content_length) {
		*ret_content_length = content_length;
	}
	ifs.close();
	// if (ifs.fail()) {
	// 	return Result<std::string, int>::err(STATUS_NOT_FOUND);  // error... why??
	// }
	return Result<std::string, int>::ok(content);
}

int HttpResponse::get_request_body(const HttpRequest &request,
								   const Config &config) {
	std::string path;
	Result<std::string, int> read_file_result;
	std::size_t content_length;

	/* path */
	path = get_resource_path(request.get_request_target(),
							 config.get_locations());

	/* read file */
	if (!is_support_content_type(path, config.get_mime_types())) {
		return 406;  // Not Acceptable
	}

	/* return status */
	read_file_result = get_file_content(path, &content_length);
	if (read_file_result.is_ok()) {
		_response_body = read_file_result.get_ok_value();
		_response_headers["Content-Length"] = to_str(content_length);
		return 200;  // OK
	}
	read_file_result = get_file_content(std::string(NOT_FOUND_PATH), &content_length);
	if (read_file_result.is_err()) {
		return 404;  // Not Found
	}
	_response_body = read_file_result.get_ok_value();
	_response_headers["Content-Length"] = to_str(content_length);
	return 404;  // Not Found
}
