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

}  // namespace

////////////////////////////////////////////////////////////////////////////////

/* return file content and content_length */
Result<std::string, int> HttpResponse::get_file_content(const std::string &file_path,
														std::size_t *ret_content_length,
														const std::map<std::string, std::string> &mime_types) {
	std::ifstream	ifs;
	std::string		content;
	std::string		buf;
	std::size_t		content_length;

	if (ret_content_length) {
		*ret_content_length = INIT_CONTENT_LENGTH;
	}

	if (!is_support_content_type(file_path, mime_types)) {
		return Result<std::string, int>::err(STATUS_NOT_ACCEPTABLE);
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
