#include <sys/stat.h>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iostream>
#include "webserv.hpp"
#include "Config.hpp"
#include "Constant.hpp"
#include "Color.hpp"
#include "FileHandler.hpp"

namespace {

bool is_regular_file(const char *path) {
	struct stat	stat_buf = {};

	if (stat(path, &stat_buf) == STAT_ERROR) {
		return false;
	}
	return S_ISREG(stat_buf.st_mode);
}

bool is_filename_only_extension(const std::string &path, size_t dot_pos) {
	if (dot_pos == 0) {
		return true;
	}
	if (path[dot_pos - 1] == PATH_DELIM) {
		return true;
	}
	return false;
}

void tolower_extension(std::string *file_extension) {
	for (size_t i = 0; i < file_extension->size(); ++i) {
		(*file_extension)[i] = static_cast<char>(std::tolower((*file_extension)[i]));
	}
}

bool has_expected_extension(const char *path_char,
							const char *expected_extension_char) {
	std::size_t dot_pos;
	std::string path, expected_extension, file_extension;

	path = std::string(path_char);

	dot_pos = path.rfind(EXTENSION_DELIM);
	if (dot_pos == std::string::npos) {
		return false;
	}
	if (is_filename_only_extension(path, dot_pos)) {
		return false;
	}

	file_extension = path.substr(dot_pos + 1);
	expected_extension = std::string(expected_extension_char);

	tolower_extension(&file_extension);
	tolower_extension(&expected_extension);
	return file_extension == expected_extension;
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

FileHandler::FileHandler(const char *path, const char *expected_extension) {
	std::string error_msg;
	Result<std::string, std::string> get_file_contents_result;

	if (!path || !expected_extension) {
		error_msg = std::string(INVALID_ARG_ERROR_MSG);
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	if (!is_valid_extension(expected_extension)) {
		error_msg = std::string(INVALID_ARG_ERROR_MSG);
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	if (!is_valid_path(path, expected_extension)) {
		error_msg = std::string(INVALID_PATH_ERROR_MSG);
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

	get_file_contents_result = get_file_contents(path);
	if (get_file_contents_result.is_err()) {
		error_msg = get_file_contents_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	this->contents_ = get_file_contents_result.get_ok_value();
	this->result_ = Result<int, std::string>::ok(OK);
}


FileHandler::FileHandler(const std::string &path) : path_(path) {}


FileHandler::~FileHandler() {}


bool FileHandler::is_valid_extension(const char *expected_extension) {
	std::string extension = std::string(expected_extension);

	if (extension.empty()) {
		return false;
	}
	for (std::size_t pos = 0; pos < extension.length(); ++pos) {
		if (!std::isalnum(extension[pos])) {
			return false;
		}
	}
	return true;
}


bool FileHandler::is_valid_path(const char *path,
											const char *expected_extension) {
	std::string path_str, extension_str;

	path_str = std::string(path);
	extension_str = std::string(expected_extension);

	if (!is_regular_file(path)) {
		return false;
	}
	if (path_str.empty() || path_str.length() <= extension_str.length()) {
		return false;
	}
	if (!has_expected_extension(path, expected_extension)) {
		return false;
	}
	return true;
}


Result<std::string, std::string> FileHandler::get_file_contents(const char *path) {
	std::string file_contents, line, error_msg;
	bool is_last_line_empty = false;
	std::size_t file_size;
	std::ifstream ifs;

	ifs.open(path, std::ifstream::in);
	if (!ifs.is_open()) {
		error_msg = std::string(INVALID_PATH_ERROR_MSG);
		return Result<std::string, std::string>::err(error_msg);
	}

	ifs.seekg(OFFSET_NONE, std::ios::end);
	file_size = ifs.tellg();
	if (FILE_SIZE_LIMIT <= file_size) {
		error_msg = std::string(FILE_SIZE_TOO_LARGE_ERROR_MSG);
		ifs.close();
		return Result<std::string, std::string>::err(error_msg);
	}

	ifs.seekg(OFFSET_NONE, std::ios::beg);
	while (std::getline(ifs, line)) {
		if (!file_contents.empty()) {
			file_contents += '\n';
		}
		file_contents += line;
		is_last_line_empty = line.empty();
	}
	if (file_contents.empty() && is_last_line_empty) {
		file_contents += '\n';
	}

	ifs.close();
	return Result<std::string, std::string>::ok(file_contents);
}


StatusCode FileHandler::delete_file() {
    Result<bool, StatusCode> is_file_result = FileHandler::is_file(this->path_);
    if (is_file_result.is_err()) {
        StatusCode error_code = is_file_result.get_err_value();
        return error_code;
    }
    bool is_file = is_file_result.get_ok_value();
    if (!is_file) {
        return Forbidden;
    }

    if (std::remove(this->path_.c_str()) != REMOVE_SUCCESS) {
        return BadRequest;
    }
    return StatusOk;
}


Result<int, std::string> FileHandler::result() const { return this->result_; }


bool FileHandler::is_err() const { return this->result().is_err(); }


const std::string &FileHandler::get_contents() const { return this->contents_; }


Result<bool, StatusCode> FileHandler::is_directory(const std::string &path) {
    return is_type(path, IsDir());
}


Result<bool, StatusCode> FileHandler::is_file(const std::string &path) {
    return is_type(path, IsFile());
}
