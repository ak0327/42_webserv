#pragma once

# include <string>
# include "Result.hpp"

namespace StringHandler {

bool is_quoted(const std::string &value);
int stoi(const std::string &str, std::size_t *idx, bool *overflow);
long stol(const std::string &str, std::size_t *idx, bool *overflow);

std::string to_string(int num);
std::string to_string(long num);

int to_digit(const char &c);


bool	is_positive_under_intmax_double(const std::string &value);  // todo: rm
bool	is_positive_and_under_intmax(const std::string &num_str);  // todo: rm


std::string	skip_lastsemicolon(const std::string &word);  // todo: rm
std::string	obtain_unquote_str(const std::string &quoted_str);  // todo: rm
bool is_positive_under_intmax_double(const std::string &value);  // todo: rm
bool is_endl_semicolon_and_no_inner_semicoron(const std::string &word);  // todo: rm
int	str_to_int(const std::string &word);  // todo: rm
std::string int_to_str(int num);  // todo: rm
std::string obtain_word_before_delimiter(const std::string &field_value, const char &delimiter);  // todo: rm
std::string obtain_word_after_delimiter(const std::string &str, char delimiter);  // todo: rm
std::string	obtain_weight(const std::string &field_value);  // todo: rm
std::string obtain_withoutows_value(const std::string &field_value_with_ows);  // todo: rm
bool is_positive_under_intmax_double(const std::string &value);  // todo: rm
std::string	skip_lastsemicolon(const std::string &word);  // todo: rm
std::string obtain_unquote_str(const std::string &quoted_str);  // todo: rm
double str_to_double(const std::string &num_str);  // todo: rm

std::string to_lower(const std::string &str);

Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t pos,
												std::size_t *end_pos,
												char tail_delimiter);

Result<std::string, int> parse_pos_to_wsp(const std::string &str,
										  std::size_t start_pos,
										  std::size_t *end_pos);


bool is_char_in_str(char c, const std::string &str);

}  // namespace StringHandler
