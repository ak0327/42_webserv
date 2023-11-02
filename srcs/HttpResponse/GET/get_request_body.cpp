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
const char NOT_FOUND_PATH[] = "www/404.html";

// mv Const.h
// const int OK = 0;
// const int ERR = -1;
const int STAT_ERROR = -1;

const char EXTENSION_DOT = '.';
const char EMPTY_STR[] = "";
const std::size_t INIT_CONTENT_LENGTH = 0;

// ---------------------------------


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
										  std::size_t *ret_content_length,
										  const std::map<std::string, std::string> &mime_types) {
	std::ifstream	ifs;
	std::string		content;
	std::string		buf;
	std::size_t		content_length;

	if (!is_support_content_type(file_path, mime_types)) {
		return Result<std::string, int>::err(STATUS_NOT_ACCEPTABLE);
	}


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

bool is_directory(const std::string &path) {
	struct stat	stat_buf = {};

	if (stat(path.c_str(), &stat_buf) == STAT_ERROR) {
		return false;
	}
	return S_ISDIR(stat_buf.st_mode);  // todo: permission
}

Result<std::string, int> get_path_content(const std::string &path,
										  bool autoindex,
										  std::size_t *ret_content_length,
										  const std::map<std::string, std::string> &mime_types) {
	if (ret_content_length) {
		*ret_content_length = INIT_CONTENT_LENGTH;
	}

	if (autoindex && is_directory(path)) {
		return get_directory_listing(path, ret_content_length);
	} else {
		return get_file_content(path, ret_content_length, mime_types);
	}
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

	// todo: tmp
	std::map<int, std::string> err_pages;
	err_pages[404] = std::string(NOT_FOUND_PATH);
	err_pages[406] = std::string(NOT_FOUND_PATH);
	err_pages[500] = std::string(NOT_FOUND_PATH);
	// ----------------------------------


	/* return status */
	read_file_result = get_path_content(path, autoindex, &content_length, config.get_mime_types());
	if (read_file_result.is_ok()) {
		_response_body = read_file_result.get_ok_value();
		_response_headers["Content-Length"] = to_str(content_length);
		return STATUS_OK;
	}

	err_code = read_file_result.get_err_value();
	err_page_path = err_pages[err_code];
	read_file_result = get_file_content(err_page_path, &content_length, config.get_mime_types());
	if (read_file_result.is_err()) {
		return STATUS_NOT_FOUND;
	}
	_response_body = read_file_result.get_ok_value();
	_response_headers["Content-Length"] = to_str(content_length);
	return STATUS_NOT_FOUND;
}
