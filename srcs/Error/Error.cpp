#include <cstring>
#include <string>
#include <sstream>
#include "Error.hpp"

namespace {
	bool is_pos_last_character(const std::string &str, std::string::size_type pos) {
		return str.size() == pos + 1;
	}

	std::string get_file_name(const std::string &filepath) {
		std::string::size_type pos = filepath.rfind('/');
		if (pos == std::string::npos || is_pos_last_character(filepath, pos)) {
			return filepath;
		}
		return filepath.substr(pos + 1);
	}
}  // namespace

std::string create_error_info(const std::string &err_str, const std::string &filepath, int line) {
	std::ostringstream err_info;
	err_info << err_str << " (" << get_file_name(filepath) << ", L" << line << ")";
	return err_info.str();
}

std::string create_error_info(const char *err_str, const std::string &filepath, int line) {
	std::ostringstream err_info;
	err_info << err_str << " (" << get_file_name(filepath) << ", L" << line << ")";
	return err_info.str();
}

std::string create_error_info(int err_no, const std::string &filepath, int line) {
	std::ostringstream err_info;
	err_info << strerror(err_no) << " (" << get_file_name(filepath) << ", L" << line << ")";
	return err_info.str();
}
