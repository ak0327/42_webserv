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


bool	is_positive_under_intmax_double(const std::string &value);
bool	is_positive_and_under_intmax(const std::string &num_str);


std::string	skip_lastsemicolon(const std::string &word);
std::string	obtain_unquote_str(const std::string &quoted_str);
bool is_positive_under_intmax_double(const std::string &value);
bool is_endl_semicolon_and_no_inner_semicoron(const std::string &word);
int	str_to_int(const std::string &word);
std::string int_to_str(int num);
std::string obtain_word_before_delimiter(const std::string &field_value, const char &delimiter);
std::string obtain_word_after_delimiter(const std::string &str, char delimiter);
std::string	obtain_weight(const std::string &field_value);
std::string obtain_withoutows_value(const std::string &field_value_with_ows);
bool is_positive_under_intmax_double(const std::string &value);
std::string	skip_lastsemicolon(const std::string &word);
std::string obtain_unquote_str(const std::string &quoted_str);
double str_to_double(const std::string &num_str);

std::string to_lower(const std::string &str);

Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t pos,
												char tail_delimiter,
												std::size_t *end_pos);

}  // namespace StringHandler
