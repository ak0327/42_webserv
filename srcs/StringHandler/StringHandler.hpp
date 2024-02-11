#pragma once

# include <string>
# include "Result.hpp"

namespace StringHandler {

bool is_quoted(const std::string &value);
bool is_char_in_str(char c, const std::string &str);

int to_digit(const char &c);
int stoi(const std::string &str, std::size_t *idx, bool *overflow);

long stol(const std::string &str, std::size_t *idx, bool *overflow);

std::string to_string(int num);
std::string to_string(long num);
std::string to_lower(const std::string &str);

Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t pos,
												std::size_t *end_pos,
												char tail_delimiter);

Result<std::string, int> parse_pos_to_wsp(const std::string &str,
										  std::size_t start_pos,
										  std::size_t *end_pos);


}  // namespace StringHandler
