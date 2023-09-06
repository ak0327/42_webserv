#pragma once

# include <string>

std::string create_error_info(const std::string &err_str, const std::string &file, int line);
std::string create_error_info(const char *err_str, const std::string &file, int line);
std::string create_error_info(int err_no, const std::string &file, int line);
