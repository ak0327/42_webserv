#include <ctype.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "Date.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"

namespace {

double get_integer_part(const std::string &str, size_t pos) {
	if (str.length() < pos) {
		return ERR;
	}
	return StringHandler::to_digit(str[pos]);
}

double get_fractional_part(const std::string &str_after_decimal_point,
						   size_t *precision_idx) {
	double	digit, num;
	int		precision_num;
	size_t	pos;

	num = 0;
	digit = 1;
	pos = 0;
	while (isdigit(str_after_decimal_point[pos])) {
		precision_num = StringHandler::to_digit(str_after_decimal_point[pos]);
		num = num * 10 + precision_num;
		digit *= 10;
		++pos;
	}
	*precision_idx = pos;
	num /= digit;
	return num;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

namespace HttpMessageParser {

// todo: test
std::string obtain_word_before_delimiter(const std::string &field_value,
										 const char &delimiter)
{
	return field_value.substr(0, field_value.find(delimiter));
}

// todo: test
std::string obtain_word_after_delimiter(const std::string &str, char delimiter)
{
	return str.substr(str.find(delimiter) + 1);
}

// todo: test
std::string	obtain_weight(const std::string &field_value)
{
	return (obtain_word_after_delimiter(field_value, '='));
}

// todo: test
std::string obtain_withoutows_value(const std::string &field_value_with_ows)
{
	size_t		before_pos = 0;
	size_t		after_pos = field_value_with_ows.length() - 1;

	if (field_value_with_ows.empty())
		return "";
	while (is_whitespace(field_value_with_ows[before_pos])
			&& before_pos != field_value_with_ows.length())
		++before_pos;
	while (is_whitespace(field_value_with_ows[after_pos])
			&& after_pos != 0)
		--after_pos;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}

////////////////////////////////////////////////////////////////////////////////

// DIGIT = %x30-39; 10 進数字（ 0-9 ）
// sign, space is not allowed for Request message
int to_integer_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	int			num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stoi(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

// delta-seconds = 1*DIGIT
// The delta-seconds rule specifies a non-negative integer
int to_delta_seconds(const std::string &str, bool *succeed) {
	return to_integer_num(str, succeed);
}

long to_long_num(const std::string &str, bool *succeed) {
	bool		is_success = false, is_overflow;
	long		num = 0;
	std::size_t	idx = 0;

	if (succeed) { *succeed = is_success; }
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = StringHandler::stol(str, &idx, &is_overflow);
	if (str[idx] == '\0' && !is_overflow) {
		is_success = true;
	}
	if (succeed && !is_overflow) { *succeed = is_success; }
	return num;
}

long to_length(const std::string &str, bool *succeed) {
	return to_long_num(str, succeed);
}

// HTTP-version	= HTTP-name "/" DIGIT "." DIGIT
// qvalue = ( "0" [ "." 0*3DIGIT ] )
//        / ( "1" [ "." 0*3("0") ] )
//
//  1.234
//    ^^^ precision_digit = 3
double to_floating_num(const std::string &str,
					   size_t precision_digit,
					   bool *succeed) {
	bool		is_success;
	double 		num, precision_num;
	std::size_t	pos, precision_idx;

	is_success = false;
	if (succeed) { *succeed = is_success; }
	num = 0;
	pos = 0;
	if (!std::isdigit(str[pos])) {
		return num;
	}
	num = get_integer_part(str, pos);
	++pos;

	if (str[pos] != DECIMAL_POINT) {
		if (str[pos] == '\0') {
			is_success = true;
		}
		if (succeed) { *succeed = is_success; }
		return num;
	}
	++pos;

	precision_num = get_fractional_part(&str[pos],
										&precision_idx);
	num += precision_num;

	if (str[pos + precision_idx] == '\0' && precision_idx <= precision_digit) {
		is_success = true;
	}
	if (succeed) { *succeed = is_success; }
	return num;
}

// if double colon not found, returns error
Result<std::size_t, int> get_double_colon_pos(const std::string &str,
											  std::size_t start_pos) {
	std::size_t pos;

	if (str.empty() || str.length() <= start_pos) {
		return Result<std::size_t, int>::err(ERR);
	}
	pos = start_pos;
	while (str[pos] && str[pos + 1]) {
		if (str[pos] == ':' && str[pos + 1] == ':') {
			return Result<std::size_t, int>::ok(pos);
		}
		++pos;
	}
	return Result<std::size_t, int>::err(ERR);
}

Result<std::string, int> parse_uri_host(const std::string &field_value,
										std::size_t start_pos,
										std::size_t *end_pos) {
	std::size_t end, len;
	std::string uri_host;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;

	skip_uri_host(field_value, start_pos, &end);
	if (start_pos == end) {
		return Result<std::string, int>::err(ERR);
	}
	len = end - start_pos;
	uri_host = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(uri_host);
}

// port = *DIGIT
Result<std::string, int> parse_port(const std::string &field_value,
									std::size_t start_pos,
									std::size_t *end_pos) {
	std::size_t len, end;
	std::string port;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	*end_pos = start_pos;

	skip_port(field_value, start_pos, &end);
	if (start_pos == end) {
		return Result<std::string, int>::err(ERR);
	}
	len = end - start_pos;
	port = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(port);
}

/*
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 parameter-value BWS = BWS ( token / quoted-string )
 */
Result<int, int>
parse_parameter(const std::string &field_value,
				std::size_t start_pos,
				std::size_t *end_pos,
				std::string *ret_parameter_name,
				std::string *ret_parameter_value,
				void (*skip_parameter_name)(const std::string &,
											std::size_t,
											std::size_t *),
				void (*skip_parameter_value)(const std::string &,
											 std::size_t,
											 std::size_t *),
				char separator,
				bool is_value_optional,
				bool skip_bws) {
	std::size_t pos, end, len, tmp_pos;
	std::string name, value;
	Result<std::string, int> parse_name_result;

	if (!end_pos || !ret_parameter_name || !ret_parameter_value) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	*ret_parameter_name = std::string(EMPTY);
	*ret_parameter_value = std::string(EMPTY);
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}

	// parameter-name
	pos = start_pos;
	skip_parameter_name(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	name = field_value.substr(pos, len);
	pos += len;

	if (skip_bws) {
		skip_ows(field_value, &pos);
	}

	// separator
	if (field_value[pos] != separator) {
		if (is_value_optional) {
			*end_pos = pos;
			*ret_parameter_name = name;
			return Result<int, int>::ok(OK);
		}
		return Result<int, int>::err(ERR);
	}
	tmp_pos = pos + 1;

	if (skip_bws) {
		skip_ows(field_value, &tmp_pos);
	}

	// parameter-value
	skip_parameter_value(field_value, tmp_pos, &end);
	if (tmp_pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - tmp_pos;
	value = field_value.substr(tmp_pos, len);
	pos = end;

	// return
	*end_pos = pos;
	*ret_parameter_name = name;
	*ret_parameter_value = value;
	return Result<int, int>::ok(OK);
}

/*
 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 */
Result<std::map<std::string, std::string>, int>
parse_parameters(const std::string &field_value,
				 std::size_t start_pos,
				 std::size_t *end_pos,
				 void (*skip_parameter_name)(const std::string &,
						 					 std::size_t,
										     std::size_t *),
				 void (*skip_parameter_value)(const std::string &,
											  std::size_t,
											  std::size_t *),
				 bool skip_bws) {
	std::size_t pos, end, tmp_pos;
	std::map<std::string, std::string> parameters;
	std::string parameter_name, parameter_value;
	Result<int, int> parse_result;

	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	if (field_value[start_pos] == '\0') {
		return Result<std::map<std::string, std::string>, int>::ok(parameters);
	}

	pos = start_pos;
	while (field_value[pos]) {
		HttpMessageParser::skip_ows(field_value, &pos);
		tmp_pos = pos;
		if (field_value[tmp_pos] != ';') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++tmp_pos;
		HttpMessageParser::skip_ows(field_value, &tmp_pos);

		parse_result = parse_parameter(field_value, tmp_pos, &end,
									   &parameter_name,
									   &parameter_value,
									   skip_parameter_name,
									   skip_parameter_value,
									   '=',
									   skip_bws);
		if (parse_result.is_err()) {
			break;
		}
		if (HttpMessageParser::is_parameter_weight(parameter_name)) {
			break;
		}
		pos = end;
		parameters[parameter_name] = parameter_value;
	}

	*end_pos = pos;
	return Result<std::map<std::string, std::string>, int>::ok(parameters);
}

/*
 media-type = type "/" subtype parameters
 subtype = token
 parameters = *( OWS ";" OWS [ parameter ] )
 */
// todo:test
Result<std::string, int> parse_subtype(const std::string &field_value,
									   std::size_t start_pos,
									   std::size_t *end_pos) {
	std::size_t len;
	std::string subtype;

	if (!end_pos) { return Result<std::string, int>::err(ERR); }
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	len = 0;
	while (true) {
		if (field_value[start_pos + len] == '\0') { break; }
		if (field_value[start_pos + len] == SP) { break; }
		if (field_value[start_pos + len] == ';') { break; }
		++len;
	}
	if (len == 0) {
		return Result<std::string, int>::err(ERR);
	}
	subtype = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(subtype);
}

/*
 media-type = type "/" subtype parameters

 type = token
 subtype = token

 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
// todo:test
Result<int, int> parse_madia_type(const std::string &field_value,
								  std::size_t start_pos,
								  std::size_t *end_pos,
								  std::string *ret_type,
								  std::string *ret_subtype,
								  std::map<std::string, std::string> *parameters) {
	std::size_t pos, end;
	Result<std::string, int> type_result, subtype_result;
	Result<std::map<std::string, std::string>, int> parameters_result;

	if (!end_pos || !ret_type || !ret_subtype || !parameters) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	type_result = StringHandler::parse_pos_to_delimiter(field_value,
														pos, &end, '/');
	if (type_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*ret_type = type_result.get_ok_value();
	pos = end;

	if (field_value[pos] != '/') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	subtype_result = parse_subtype(field_value, pos, &end);
	if (subtype_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*ret_subtype = subtype_result.get_ok_value();
	pos = end;

	parameters_result = HttpMessageParser::parse_parameters(field_value,
															pos, &end,
															skip_token,
															skip_token_or_quoted_string);
	if (parameters_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*parameters = parameters_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
 MAP_FIELD_VALUER = PARAMETER * ( OWS "," OWS PARAMETER)
 PARAMETER        = PARAMETER-NAME SEPARATOR PARAMETER-VALUE   ; optional = false
 PARAMETER        = PARAMETER-NAME [SEPARATOR PARAMETER-VALUE] ; optional = true
 */
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
					   char separator,
					   bool is_value_optional) {
	Result<int, int> parse_result;
	Result<std::size_t, int> skip_result;
	std::string parameter_name, parameter_value;
	std::map<std::string, std::string> parameters;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (field_value[pos]) {
		parse_result = HttpMessageParser::parse_parameter(field_value,
														  pos, &end,
														  &parameter_name,
														  &parameter_value,
														  skip_parameter_name,
														  skip_parameter_value,
														  separator,
														  is_value_optional);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		parameters[parameter_name] = parameter_value;
		pos = end;

		skip_result = skip_to_next_parameter(field_value, pos);
		if (skip_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = skip_result.get_ok_value();
	}
	return Result<std::map<std::string, std::string>, int>::ok(parameters);
}

/*
 FIELD_NAME   = #MAP_ELEMENT
 MAP_ELEMENT  = KEY [ SEPARATOR VALUE ]
 1#element => element *( OWS "," OWS element )
 */
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
														   std::size_t *)) {
	std::size_t pos, end, len;

	if (!end_pos || !key || !value) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	*key = std::string(EMPTY);
	*value = std::string(EMPTY);
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}

	// key
	pos = start_pos;
	skip_key_func(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*key = field_value.substr(pos, len);
	pos += len;

	// separator
	if (field_value[pos] != separator) {
		*end_pos = pos;
		return Result<int, int>::ok(OK);
	}
	++pos;

	// value
	skip_value_func(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*value = field_value.substr(pos, len);

	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

Result<std::set<std::map<std::string, std::string> >, int>
parse_map_set_field_values(const std::string &field_value,
						   Result<std::map<std::string, std::string>, int> (*parse_func)(const std::string &,
																						 std::size_t,
																						 std::size_t *)) {
	std::set<std::map<std::string, std::string> > map_set;
	std::map<std::string, std::string> map_element;
	std::size_t pos, end;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<std::size_t, int> skip_result;

	if (field_value.empty()) {
		return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
	}

	pos = 0;
	while (field_value[pos]) {
		parse_result = parse_func(field_value, pos, &end);
		if (parse_result.is_err()) {
			return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
		}
		map_element = parse_result.get_ok_value();
		pos = end;

		map_set.insert(map_element);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
		}
		pos = skip_result.get_ok_value();
	}
	return Result<std::set<std::map<std::string, std::string> >, int>::ok(map_set);
}

/*
 field-name: field_value
 field_value = VALUE *( ";" MAP_VALUES )
*/
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
																							   std::size_t *)) {
	Result<std::string, int> value_result;
	Result<std::map<std::string, std::string>, int> map_values_result;
	std::size_t pos, end;


	if (!end_pos || !ret_value || !ret_map_values || !parse_value_func || !parse_map_values) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}
	pos = start_pos;

	value_result = parse_value_func(field_value, pos, &end);
	if (value_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*ret_value = value_result.get_ok_value();

	pos = end;
	*end_pos = pos;

	if (field_value[pos] != ';') {
		return Result<int, int>::ok(OK);
	}

	map_values_result = parse_map_values(field_value, pos, &end);
	if (map_values_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*ret_map_values = map_values_result.get_ok_value();

	pos = end;
	*end_pos = pos;
	return Result<int, int>::ok(OK);
}


}  // namespace HttpMessageParser
