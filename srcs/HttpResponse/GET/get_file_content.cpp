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

// ---------------------------------

bool is_support_content_type(const std::string &path,
							 const std::map<std::string, std::string> &mime_types) {
	std::string extension;
	std::map<std::string, std::string>::const_iterator itr;

	extension = get_extension(path);
	itr = mime_types.find(extension);
	return itr != mime_types.end();
}

}  // namespace

// todo: mv lib
std::string get_extension(const std::string &path) {
	std::size_t ext_pos;

	ext_pos = path.find_last_of(EXTENSION_DOT);
	if (ext_pos == std::string::npos) {
		return std::string(EMPTY_STR);
	}
	return path.substr(ext_pos + 1);
}

////////////////////////////////////////////////////////////////////////////////

/* return file content and content_length */
Result<std::string, int> HttpResponse::get_file_content(const std::string &file_path,
														const std::map<std::string, std::string> &mime_types) const {
	std::ifstream	file;
	std::string		content;
	std::string		buf;

	if (!is_support_content_type(file_path, mime_types)) {
		return Result<std::string, int>::err(STATUS_NOT_ACCEPTABLE);
	}

	// todo: API?
	file.open(file_path.c_str());
	if (file.fail()) {
		return Result<std::string, int>::err(STATUS_NOT_FOUND);
	}

	content = EMPTY_STR;
	while (std::getline(file, buf)) {
		content.append(buf + (file.eof() ? "" : "\n"));
	}
	file.close();
	// if (ifs.fail()) {
	// 	return Result<std::string, int>::err(STATUS_NOT_FOUND);  // error... why??
	// }
	return Result<std::string, int>::ok(content);
}
