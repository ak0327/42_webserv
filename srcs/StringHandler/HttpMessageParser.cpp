#include <ctype.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <map>
#include <string>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "Date.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"
#include "Result.hpp"

namespace {

double get_integer_part(const std::string &str, size_t idx) {
	if (str.length() < idx) {
		return ERR;
	}
	return StringHandler::to_digit(str[idx]);
}

double get_fractional_part(const std::string &str_after_decimal_point,
						   size_t *precision_idx) {
	double	digit, num;
	int		precision_num;
	size_t	idx;

	num = 0;
	digit = 1;
	idx = 0;
	while (isdigit(str_after_decimal_point[idx])) {
		precision_num = StringHandler::to_digit(str_after_decimal_point[idx]);
		num = num * 10 + precision_num;
		digit *= 10;
		++idx;
	}
	*precision_idx = idx;
	num /= digit;
	return num;
}

// bool is_parameter_weight(const std::string &parameter_name,
// 						 const std::string &parameter_value) {
// 	bool succeed;
//
// 	if (parameter_name != "q") {
// 		return false;
// 	}
// 	HttpMessageParser::to_floating_num(parameter_value, 3, &succeed);
// 	return succeed;
// }

bool is_parameter_weight(const std::string &parameter_name) {
	return parameter_name == "q";
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

	if (field_value_with_ows == "")
		return "";
	while (is_whitespace(field_value_with_ows[before_pos]) == true
			&& before_pos != field_value_with_ows.length())
		++before_pos;
	while (is_whitespace(field_value_with_ows[after_pos]) == true
			&& after_pos != 0)
		--after_pos;
	if (before_pos > after_pos)
		return "";
	return (field_value_with_ows.substr(before_pos, after_pos - before_pos + 1));
}

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

// todo: test
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
	std::size_t	idx, precision_idx;

	is_success = false;
	if (succeed) { *succeed = is_success; }
	num = 0;
	idx = 0;
	if (!std::isdigit(str[idx])) {
		return num;
	}
	num = get_integer_part(str, idx);
	++idx;

	if (str[idx] != DECIMAL_POINT) {
		if (str[idx] == '\0') {
			is_success = true;
		}
		if (succeed) { *succeed = is_success; }
		return num;
	}
	++idx;

	precision_num = get_fractional_part(&str[idx],
										&precision_idx);
	num += precision_num;

	if (str[idx + precision_idx] == '\0' && precision_idx <= precision_digit) {
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
 */
// todo:test
Result<int, int> parse_parameter(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos,
								 std::string *parameter_name,
								 std::string *parameter_value) {
	std::size_t pos, end, len;
	Result<std::string, int> parse_name_result;

	if (!end_pos || !parameter_name || !parameter_value) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<int, int>::err(ERR);
	}

	// parameter-name
	pos = start_pos;
	skip_token(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*parameter_name = field_value.substr(pos, len);
	pos += len;

	// =
	if (field_value[pos] != '=') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// parameter-value
	len = 0;
	if (HttpMessageParser::is_tchar(field_value[pos])) {
		while (field_value[pos + len] && HttpMessageParser::is_tchar(field_value[pos + len])) {
			++len;
		}
	} else if (field_value[pos] == '"') {
		HttpMessageParser::skip_quoted_string(field_value, pos, &end);
		if (pos == end) {
			return Result<int, int>::err(ERR);
		}
		len = end - pos;
	} else {
		return Result<int, int>::err(ERR);
	}

	if (len == 0) {
		return Result<int, int>::err(ERR);
	}
	*parameter_value = field_value.substr(pos, len);
	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

/*
 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
// todo:test
Result<std::map<std::string, std::string>, int> parse_parameters(const std::string &field_value,
																 std::size_t start_pos,
																 std::size_t *end_pos) {
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
		tmp_pos = pos;
		HttpMessageParser::skip_ows(field_value, &tmp_pos);
		if (field_value[tmp_pos] != ';') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++tmp_pos;
		HttpMessageParser::skip_ows(field_value, &tmp_pos);

		parse_result = parse_parameter(field_value, tmp_pos, &end,
									   &parameter_name,
									   &parameter_value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		if (is_parameter_weight(parameter_name)) {
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
								  std::string *type,
								  std::string *subtype,
								  std::map<std::string, std::string> *parameters) {
	std::size_t pos, end;
	Result<std::string, int> type_result, subtype_result;
	Result<std::map<std::string, std::string>, int> parameters_result;

	if (!end_pos || !type || !subtype || !parameters) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}

	pos = start_pos;
	type_result = StringHandler::parse_pos_to_delimiter(field_value, pos,
														'/', &end);
	if (type_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*type = type_result.get_ok_value();
	pos = end;

	if (field_value[pos] != '/') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	subtype_result = parse_subtype(field_value, pos, &end);
	if (subtype_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*subtype = subtype_result.get_ok_value();
	pos = end;

	parameters_result = HttpMessageParser::parse_parameters(field_value, pos, &end);
	if (parameters_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*parameters = parameters_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

}  // namespace HttpMessageParser
