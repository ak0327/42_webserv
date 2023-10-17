#pragma once

# include <string>
# include "Constant.hpp"
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
bool is_obs_text(char c);
bool is_tchar(char c);
bool is_whitespace(char c);
bool is_qdtext(char c);
bool is_hexdig(char c);
bool is_attr_char(char c);
bool is_singleton(char c);

bool is_field_content(const std::string &str);
bool is_token(const std::string &str);
bool is_token68(const std::string &str);
bool is_ext_token(const std::string &str);

bool is_langtag(const std::string &str);
bool is_privateuse(const std::string &str);
bool is_grandfathered(const std::string &str);
bool is_language_tag(const std::string &str);
bool is_language(const std::string &str);
bool is_script(const std::string &str);
bool is_region(const std::string &str);
bool is_variant(const std::string &str);
bool is_extension(const std::string &str);

bool is_etag(char c);
bool is_opaque_tag(const std::string &str);
bool is_entity_tag(const std::string &str);
bool is_base_64_value_non_empty(const std::string &str);

bool is_absolute_uri(const std::string &str);
bool is_partial_uri(const std::string &str);

bool is_irregular(const std::string &str);
bool is_regular(const std::string &str);

bool is_header_body_separator(const std::string &line_end_with_cr);

bool is_quoted_string(const std::string &str);
bool is_quoted_pair(const std::string &str, std::size_t pos);

bool is_pct_encoded(const std::string &str, std::size_t pos);

/* validate */
bool is_valid_method(const std::string &method);
bool is_valid_request_target(const std::string &request_target);
bool is_valid_http_version(const std::string &http_version);

bool is_valid_field_name(const std::string &field_name);
bool is_valid_field_name_syntax(const std::string &field_name);
bool is_valid_field_value_syntax(const std::string &field_value);
bool is_ignore_field_name(const std::string &field_name);

bool is_valid_day1(int year, int month, int day);
bool is_valid_time_of_day(int hour, int minute, int second);
bool is_valid_day_name(const std::string &day_name, int year, int month, int day);

std::string parse_uri_host(const std::string &str,
						   std::size_t start_pos,
						   std::size_t *end_pos);
std::string parse_port(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);

Result<date_format, int> parse_http_date(const std::string &http_date,
										 std::string *day_name,
										 std::string *day,
										 std::string *month,
										 std::string *year,
										 std::string *hour,
										 std::string *minute,
										 std::string *second,
										 std::string *gmt);

Result<int, int> validate_http_date(date_format format,
									const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt);

void skip_ows(const std::string &str, std::size_t *pos);
void skip_quoted_string(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);
void skip_language_tag(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);
void skip_langtag(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);
void skip_privateuse(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos);
void skip_grandfathered(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);
void skip_script(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos);
void skip_region(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos);
void skip_variant(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);
void skip_extension(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);
void skip_extlang(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);
void skip_language(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);
}  // namespace HttpMessageParser
