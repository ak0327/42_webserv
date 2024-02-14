#pragma once

# include <string>

#define CREATE_ERROR_INFO_STR(err_str) create_error_info(err_str, __FILE__, __LINE__)
#define CREATE_ERROR_INFO_CSTR(err_str) create_error_info(err_str, __FILE__, __LINE__)
#define CREATE_ERROR_INFO_ERRNO(err_no) create_error_info(err_no, __FILE__, __LINE__)

std::string create_error_info(const std::string &err_str, const std::string &file, int line);
std::string create_error_info(const char *err_str, const std::string &file, int line);
std::string create_error_info(int err_no, const std::string &file, int line);
