#pragma once

# include <string>
# include "Result.hpp"

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
int to_delta_seconds(const std::string &str, bool *succeed);

long to_long_num(const std::string &str, bool *succeed);
long to_length(const std::string &str, bool *succeed);

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

bool is_valid_method(const std::string &method);
bool is_valid_request_target(const std::string &request_target);
bool is_valid_http_version(const std::string &http_version);

bool is_trailer_allowed_field_name(const std::string &field_name);

bool is_valid_day1(int year, int month, int day);
bool is_valid_time_of_day(int hour, int minute, int second);
bool is_valid_day_name(const std::string &day_name, int year, int month, int day);

Result<int, int> parse_http_date(const std::string &http_date,
								 std::string *day_name,
								 std::string *day,
								 std::string *month,
								 std::string *year,
								 std::string *hour,
								 std::string *minute,
								 std::string *second,
								 std::string *gmt);

Result<int, int> validate_http_date(const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt);
}  // namespace HttpMessageParser
