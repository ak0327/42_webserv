#pragma once

# include <map>
# include <set>
# include <string>
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Result.hpp"

namespace HttpMessageParser {

int to_integer_num(const std::string &str, bool *succeed);
int to_delta_seconds(const std::string &str, bool *succeed);

long to_long_num(const std::string &str, bool *succeed);
long to_length(const std::string &str, bool *succeed);

double to_floating_num(const std::string &str,
					   size_t precision_digit,
					   bool *succeed);

////////////////////////////////////////////////////////////////////////////////

bool is_delimiters(char c);
bool is_vchar(char c);
bool is_field_vchar(char c);
bool is_obs_text(char c);
bool is_tchar(char c);
bool is_ctext(char c);
bool is_whitespace(char c);
bool is_dtext(char c);
bool is_obs_dtext(char c);
bool is_qdtext(char c);
bool is_hexdig(char c);
bool is_attr_char(char c);
bool is_singleton(char c);
bool is_etag(char c);
bool is_unreserved(char c);
bool is_sub_delims(char c);
bool is_atext(char c);

bool is_end_with_cr(const std::string &str);
bool is_positive_under_intmax_double(const std::string &str);
bool is_print(const std::string &str);
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
bool is_opaque_tag(const std::string &str);
bool is_entity_tag(const std::string &str);
bool is_absolute_uri(const std::string &str);
bool is_partial_uri(const std::string &str);
bool is_irregular(const std::string &str);
bool is_regular(const std::string &str);
bool is_base_64_value_non_empty(const std::string &str);
bool is_quoted_string(const std::string &str);
bool is_http_date(const std::string &str);
bool is_dec_octet(const std::string &str);
bool is_ipv4address(const std::string &str);
bool is_ipv6address(const std::string &str);
bool is_ipvfuture(const std::string &str);
bool is_ip_literal(const std::string &str);
bool is_reg_name(const std::string &str);
bool is_valid_method(const std::string &str);
bool is_valid_request_target(const std::string &str);
bool is_valid_http_version(const std::string &str);
bool is_valid_field_name(const std::string &str);
bool is_valid_field_name_syntax(const std::string &str);
bool is_valid_field_value_syntax(const std::string &str);
bool is_scheme(const std::string &str);
bool is_uri_host(const std::string &str);
bool is_port(const std::string &str);
bool is_pchar(const std::string &str);
bool is_query(const std::string &str);
bool is_segment(const std::string &str);
bool is_segment_nz(const std::string &str);
bool is_segment_nz_nc(const std::string &str);
bool is_path_abempty(const std::string &str);
bool is_path_absolute(const std::string &str);
bool is_path_noscheme(const std::string &str);
bool is_path_rootless(const std::string &str);
bool is_userinfo(const std::string &str);
bool is_authority(const std::string &str);
bool is_mailbox(const std::string &str);
bool is_atom(const std::string &str);
bool is_origin_form(const std::string &str);
bool is_absolure_form(const std::string &str);
bool is_authority_form(const std::string &str);
bool is_asterisk_form(const std::string &str);

bool is_path_empty(const std::string &str, std::size_t start_pos);

bool is_langtag_option(const std::string &str,
					   std::size_t start_pos,
					   void (*skip_func)(const std::string &,
										 std::size_t,
										 std::size_t *));

bool is_header_body_separator(const std::string &line_end_with_cr);
bool is_quoted_pair(const std::string &str, std::size_t start_pos);
bool is_pct_encoded(const std::string &str, std::size_t pos);
bool is_ignore_field_name(const std::string &field_name);

bool is_valid_day1(int year, int month, int day);
bool is_valid_time_of_day(int hour, int minute, int second);
bool is_valid_day_name(const std::string &day_name, int year, int month, int day);

bool is_valid_type(const std::string &type);
bool is_valid_subtype(const std::string &subtype);
bool is_valid_parameters(const std::map<std::string, std::string> &parameters);

bool is_parameter_weight(const std::string &parameter_name,
						 const std::string &parameter_value);
bool is_parameter_weight(const std::string &parameter_name);

////////////////////////////////////////////////////////////////////////////////

void skip_ows(const std::string &str, std::size_t *pos);

void skip_token(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos);

void skip_quoted_string(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_token_or_quoted_string(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos);

void skip_quoted_pair(const std::string &str,
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

void skip_product(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);

void skip_comment(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);

void skip_reg_name(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);

void skip_ipv4address(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_ipv6address(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_ipvfuture(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_ip_literal(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos);

void skip_dec_octet(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_h16(const std::string &str,
			  std::size_t start_pos,
			  std::size_t *end_pos);

void skip_ls32(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos);

void skip_absolute_uri(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);

void skip_partial_uri(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_scheme(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos);

void skip_pct_encoded(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_pchar(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos);

void skip_segment(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);

void skip_query(const std::string &str,
				std::size_t start_pos,
				std::size_t *end_pos);

void skip_fragment(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);

void skip_segment_nz(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos);

void skip_segment_nz_nc(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_path_abempty(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);

void skip_path_absolute(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_path_noscheme(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_path_rootless(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_userinfo(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);

void skip_uri_host(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);

void skip_port(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos);

void skip_authority(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_relative_part(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

void skip_hier_part(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_mailbox(const std::string &str,
				  std::size_t start_pos,
				  std::size_t *end_pos);

void skip_atom(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos);

void skip_word(const std::string &str,
			   std::size_t start_pos,
			   std::size_t *end_pos);

void skip_dot_atm_text(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);

void skip_dot_atom(const std::string &str,
				   std::size_t start_pos,
				   std::size_t *end_pos);

void skip_domain_literal(const std::string &str,
						 std::size_t start_pos,
						 std::size_t *end_pos);

void skip_domain(const std::string &str,
				 std::size_t start_pos,
				 std::size_t *end_pos);

void skip_obs_local_part(const std::string &str,
						 std::size_t start_pos,
						 std::size_t *end_pos);

void skip_local_part(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos);

void skip_addr_spec(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_int_range(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos);

void skip_suffix_range(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos);

void skip_other_range(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_origin_form(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos);

void skip_absolute_path(const std::string &str,
						std::size_t start_pos,
						std::size_t *end_pos);

Result<std::size_t, int> skip_ows_delimiter_ows(const std::string &field_value,
												char delimiter,
												std::size_t start_pos);

Result<std::size_t, int> skip_ows_comma_ows(const std::string &field_value,
											std::size_t start_pos);

Result<std::size_t, int> skip_noop(const std::string &field_value,
								   std::size_t start_pos);

////////////////////////////////////////////////////////////////////////////////

Result<std::size_t, int> get_double_colon_pos(const std::string &str,
											  std::size_t start_pos);


Result<std::string, int> parse_uri_host(const std::string &field_value,
										std::size_t start_pos,
										std::size_t *end_pos);

Result<std::string, int> parse_port(const std::string &field_value,
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

Result<int, int> parse_madia_type(const std::string &field_value,
								  std::size_t start_pos,
								  std::size_t *end_pos,
								  std::string *ret_type,
								  std::string *ret_subtype,
								  std::map<std::string, std::string> *parameters);

Result<std::string, int> parse_subtype(const std::string &field_value,
									   std::size_t start_pos,
									   std::size_t *end_pos);

Result<int, int> parse_parameter(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos,
								 std::string *ret_parameter_name,
								 std::string *ret_parameter_value,
								 void (*skip_parameter_name)(const std::string &, std::size_t, std::size_t *),
								 void (*skip_parameter_value)(const std::string &, std::size_t, std::size_t *),
								 char separator = EQUAL_SIGN,
								 bool is_value_optional = false,
								 bool skip_bws = false);

Result<std::map<std::string, std::string>, int>
parse_parameters(const std::string &field_value,
				 std::size_t start_pos,
				 std::size_t *end_pos,
				 void (*skip_parameter_name)(const std::string &, std::size_t, std::size_t *),
				 void (*skip_parameter_value)(const std::string &, std::size_t, std::size_t *),
				 bool skip_bws = false);

Result<int, int> parse_map_element(const std::string &field_value,
								   std::size_t start_pos,
								   std::size_t *end_pos,
								   char separator,
								   std::string *key,
								   std::string *value,
								   void (*skip_key_func)(const std::string &,
														 std::size_t,
														 std::size_t *),
								  void (*skip_value_func)(const std::string &,
														  std::size_t,
														  std::size_t *));

Result<std::map<std::string, std::string>, int>
parse_map_field_values(const std::string &field_value,
					   void (*skip_parameter_name)(const std::string &,
												   std::size_t,
												   std::size_t *),
					   void (*skip_parameter_value)(const std::string &,
													std::size_t,
													std::size_t *),
					   Result<std::size_t, int> (*skip_to_next_parameter)(const std::string &,
																		  std::size_t),
					   char separator = EQUAL_SIGN,
					   bool is_value_optional = false);

Result<std::set<std::map<std::string, std::string> >, int>
parse_map_set_field_values(const std::string &field_value,
						   Result<std::map<std::string, std::string>, int> (*parse_func)(const std::string &,
																						 std::size_t,
																						 std::size_t *));

Result<int, int>
parse_value_and_map_values(const std::string &field_value,
						   std::size_t start_pos,
						   std::size_t *end_pos,
						   std::string *ret_value,
						   std::map<std::string, std::string> *ret_map_values,
						   Result<std::string, int> (*parse_value_func)(const std::string &,
																		std::size_t,
																		std::size_t *),
						   Result<std::map<std::string, std::string>, int> (*parse_map_values)(const std::string &,
																							   std::size_t,
																							   std::size_t *));

Result<int, int> validate_http_date(date_format format,
									const std::string &day_name,
									const std::string &day,
									const std::string &month,
									const std::string &year,
									const std::string &hour,
									const std::string &minute,
									const std::string &second,
									const std::string &gmt);


Method get_method(const std::string &method);

std::string decode(const std::string &encoded);
std::string normalize(const std::string &path);


}  // namespace HttpMessageParser
