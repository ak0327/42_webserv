#pragma once

# include <string>

namespace HttpMessageParser {

bool is_end_with_cr(const std::string &value);
bool is_positive_under_intmax_double(const std::string &value);
bool is_printable(const std::string &value);

std::string	obtain_word_after_delimiter(const std::string &str, char delimiter);
std::string	obtain_withoutows_value(const std::string &field_value_with_ows);
std::string	obtain_weight(const std::string &field_value);
std::string	obtain_word_before_delimiter(const std::string &field_value, const char &delimiter);

////////////////////////////////////////////////////////////////////////////////

int to_integer_num(const std::string &str, bool *succeed);

double to_floating_num(const std::string &str,
					   size_t precision_digit,
					   bool *succeed);

bool is_delimiters(char c);
bool is_vchar(char c);
bool is_field_vchar(char c);
bool is_field_content(const std::string &str);
bool is_obs_text(char c);
bool is_tchar(char c);
bool is_token(const std::string &str);
bool is_whitespace(char c);

}  // namespace HttpMessageParser
