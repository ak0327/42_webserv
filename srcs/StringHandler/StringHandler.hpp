#pragma once

# include <string>
# include "Result.hpp"

namespace StringHandler {

bool is_quoted(const std::string &value);
bool is_char_in_str(char c, const std::string &str);
bool is_valid_file_name(const std::string &path);
bool is_valid_extension(const std::string &path);
bool has_trailing_slash(const std::string &path);

int to_digit(const char &c);
int stoi(const std::string &str, std::size_t *idx, bool *overflow);

long stol(const std::string &str, std::size_t *idx, bool *overflow);

std::string to_string(int num);
std::string to_string(long num);
std::string to_string(std::size_t num);
std::string to_lower(const std::string &str);
std::string to_upper(const std::string &str);

Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t pos,
												std::size_t *end_pos,
												char tail_delimiter);

Result<std::string, int> parse_pos_to_wsp(const std::string &str,
										  std::size_t start_pos,
										  std::size_t *end_pos);

std::string get_file_name(const std::string &path);
std::string get_extension(const std::string &path);
std::string unquote(const std::string &quoted);
std::string decode(const std::string &encoded);
std::string normalize_to_absolute_path(const std::string &path);

}  // namespace StringHandler
