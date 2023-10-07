#pragma once

# include <string>

namespace StringHandler {

bool is_end_with_cr(const std::string &value);
bool is_positive_under_intmax_double(const std::string &value);
bool is_quoted(const std::string &value);
bool is_endl_semicolon_and_no_inner_semicoron(const std::string &word);
bool is_ows(const char &c);
bool is_printable_content(const std::string &value);
bool is_positive_and_under_intmax(const std::string &word);
double str_to_double(const std::string &num_str);

int str_to_int(const std::string &word);
int to_digit(const char &c);

std::string	int_to_str(int num);
std::string	obtain_word_after_delimiter(const std::string &str, char delimiter);
std::string	obtain_unquote_str(const std::string &quoted_str);
std::string	obtain_withoutows_value(const std::string &field_value_with_ows);
std::string	obtain_weight(const std::string &field_value);
std::string	obtain_word_before_delimiter(const std::string &field_value, const char &delimiter);
std::string	skip_lastsemicolon(const std::string &word);

int stoi(const std::string &str, std::size_t *idx, bool *overflow);
int to_integer_num(const std::string &str, bool *succeed);

double to_floating_num(const std::string &str,
					   size_t precision_digit,
					   bool *succeed);

}  // namespace StringHandler
