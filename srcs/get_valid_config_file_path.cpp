#include <sys/stat.h>
#include <iostream>
#include "webserv.hpp"

// can't operate nginx
//   o-r nginx.conf
//   o-x nginx/
static bool has_file_read_permission(const char *path) {
	struct stat	stat_buf = {};

	if (stat(path, &stat_buf) == STAT_ERROR) {
		return false;
	}
	if (!S_ISREG(stat_buf.st_mode)) {
		return false;
	}
	return stat_buf.st_mode & S_IRUSR;
}

static bool is_filename_only_extension(const std::string &path, size_t dot_pos) {
	if (dot_pos == 0) {
		return true;
	}
	if (path[dot_pos - 1] == PATH_DELIM) {
		return true;
	}
	return false;
}

static bool is_valid_extension(const std::string &path,
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
	return file_extension == expected_extension;
}

// todo: static, tmp non-static for test
bool is_valid_config_file_path(const char *path) {
	if (!is_valid_extension(path, CONFIG_FILE_EXTENSION)) {
		return false;
	}
	if (!has_file_read_permission(path)) {
		return false;
	}
	return true;
}

// if config file is not given, path is 'default'  todo: empty string ?
std::string get_valid_config_file_path(int argc, char **argv) {
	const char	*path = argv[CONFIG_FILE_INDEX];

	if (argc == EXECUTABLE_FILE_ONLY_ARGC) {
		return std::string(DEFAULT_CONFIG);
	}
	if (!is_valid_config_file_path(path)) {
		throw std::invalid_argument(INVALID_PATH_ERROR_MSG);
	}
	return std::string(path);
}
