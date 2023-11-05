#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include "Color.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

namespace {

// tmp -----------------------------
// const char PATH_ROOT[] = "/";
// const char PATH_INDEX[] = "index.html";

// mv Const.h
// const int OK = 0;
// const int ERR = -1;
const int STAT_ERROR = -1;

const std::size_t INIT_CONTENT_LENGTH = 0;

// ---------------------------------

// todo: int, double,...
std::string to_str(std::size_t num) {
	std::ostringstream oss;

	oss << num;
	return oss.str();
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

bool is_directory(const std::string &path) {
	struct stat	stat_buf = {};

	if (stat(path.c_str(), &stat_buf) == STAT_ERROR) {
		return false;
	}
	return S_ISDIR(stat_buf.st_mode);  // todo: permission
}

bool is_cgi_file(const std::string &path) {
	const std::string extension = get_extension(path);
	return extension == "py" || extension == "php";  // tmp
}

Result<std::string, int> HttpResponse::get_path_content(const std::string &path,
														bool autoindex,
														std::size_t *ret_content_length,
														const std::map<std::string, std::string> &mime_types) const {
	Result<std::string, int> get_content_result;
	std::string content;

	if (ret_content_length) {
		*ret_content_length = INIT_CONTENT_LENGTH;
	}

	if (autoindex && is_directory(path)) {
		get_content_result = get_directory_listing(path);
	} else if (is_cgi_file(path)) {
		// todo ------------------
		// create_cgi_request();
		// get_cgi_response();
		// get_cgi_field_lines();
		// get_cgi_request_body();
		// -----------------------
		get_content_result = get_cgi_result(path, "");
	} else {
		get_content_result = get_file_content(path, mime_types);
	}

	if (ret_content_length && get_content_result.is_ok()) {
		*ret_content_length = get_content_result.get_ok_value().length();
	}
	return get_content_result;
}

int HttpResponse::get_request_body(const HttpRequest &request,
								   const Config &config,
								   const std::string &path,
								   bool autoindex) {
	Result<std::string, int> read_file_result;
	std::size_t content_length;
	int err_code;
	std::string err_page_path;
	(void)request;

	read_file_result = get_path_content(path,
										autoindex,
										&content_length,
										config.get_mime_types());
	if (read_file_result.is_ok()) {
		_response_body = read_file_result.get_ok_value();
		_response_headers["Content-Length"] = to_str(content_length);
		return STATUS_OK;
	}

	err_code = read_file_result.get_err_value();
	_response_body = _error_pages[err_code];
	_response_headers["Content-Length"] = to_str(_response_body.length());  // todo: use original to_str()
	return err_code;
}
