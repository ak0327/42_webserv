#include <sys/stat.h>
#include <iostream>
#include "webserv.hpp"

// can't operate nginx
//   o-r nginx.conf
//   o-x nginx/

namespace {
	const std::string CONFIG_FILE_EXTENSION = "conf";
	char PATH_DELIM = '/';
	char EXTENSION_DELIM = '.';
	int STAT_ERROR = -1;
	std::string INVALID_PATH_ERROR_MSG = "[Error] invalid file path";

	bool has_file_owners_read_permission(const char *path) {
		struct stat	stat_buf = {};

		if (stat(path, &stat_buf) == STAT_ERROR) {
			return false;
		}
		if (!S_ISREG(stat_buf.st_mode)) {
			return false;
		}
		return stat_buf.st_mode & S_IRUSR;
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

	bool is_valid_extension(const std::string &path,
							const std::string &expected_extension) {
		size_t		dot_pos;
		std::string file_extension;

		dot_pos = path.rfind(EXTENSION_DELIM);
		if (dot_pos == std::string::npos) {
			return false;
		}
		if (is_filename_only_extension(path, dot_pos)) {
			return false;
		}
		file_extension =  path.substr(dot_pos + 1);
		tolower_extension(&file_extension);
		return file_extension == expected_extension;
	}

	bool is_valid_config_file_path(const char *path) {
		if (!is_valid_extension(path, CONFIG_FILE_EXTENSION)) {
			return false;
		}
		if (!has_file_owners_read_permission(path)) {
			return false;
		}
		return true;
	}
}  // namespace

std::string get_valid_config_file_path(const char *path) {
	if (!is_valid_config_file_path(path)) {
		throw std::invalid_argument(INVALID_PATH_ERROR_MSG);
	}
	return std::string(path);
}
