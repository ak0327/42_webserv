#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

/*
 cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                ; US-ASCII characters excluding CTLs,
                ; whitespace DQUOTE, comma, semicolon,
                ; and backslash
 */
bool is_cookie_octet(char c) {
	return (c == 0x21
			|| (0x23 <= c && c <= 0x2B)
			|| (0x2D <= c && c <= 0x3A)
			|| (0x3C <= c && c <= 0x5B)
			|| (0x5D <= c && c <= 0x7E));
}

// cookie-name = token
void skip_cookie_name(const std::string &str,
					  std::size_t start_pos,
					  std::size_t *end_pos) {
	HttpMessageParser::skip_token(str, start_pos, end_pos);
}

// cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
void skip_cookie_value(const std::string &str,
					   std::size_t start_pos,
					   std::size_t *end_pos) {
	std::size_t len;
	bool is_quoted;

	if (!end_pos) { return; }

	len = 0;
	if (str[start_pos] == '"') {
		is_quoted = true;
		++len;
	} else {
		is_quoted = false;
	}

	while (str[start_pos + len] && is_cookie_octet(str[start_pos + len])) {
		++len;
	}

	if (is_quoted) {
		if (str[start_pos + len] == '"') {
			++len;
		} else {
			return;
		}
	}
	if (len == 0) { return; }
	*end_pos = start_pos + len;
}

Result<std::size_t, int> skip_to_next_cookie_pair(const std::string &field_value,
												  std::size_t start_pos) {
	std::size_t pos;
	const std::size_t comma_and_sp_len = 2;

	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::size_t, int>::err(ERR);
	}

	pos = start_pos;
	if (field_value[pos] == ';' && field_value[pos + 1] == SP) {
		pos += comma_and_sp_len;
	}
	return Result<std::size_t, int>::ok(pos);
}

/*
 cookie-string = cookie-pair *( ";" SP cookie-pair )
 cookie-pair   = cookie-name "=" cookie-value
 */
Result<std::map<std::string, std::string>, int>
parse_valid_cookie_string(const std::string &field_value) {
	Result<int, int> parse_result;
	Result<std::size_t, int> skip_result;
	std::string cookie_name, cookie_value;
	std::map<std::string, std::string> cookie_string;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (field_value[pos]) {
		parse_result = HttpMessageParser::parse_parameter(field_value,
														  pos, &end,
														  &cookie_name, &cookie_value,
														  skip_cookie_name,
														   skip_cookie_value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		cookie_string[cookie_name] = cookie_value;
		pos = end;

		skip_result = skip_to_next_cookie_pair(field_value, pos);
		if (skip_result.is_err()) {
  			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = skip_result.get_ok_value();
	}
	return Result<std::map<std::string, std::string>, int>::ok(cookie_string);
}

Result<std::map<std::string, std::string>, int>
parse_and_validate_cookie_string(const std::string &field_value) {
	std::map<std::string, std::string> cookie_string;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	parse_result = parse_valid_cookie_string(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	cookie_string = parse_result.get_ok_value();
	return Result<std::map<std::string, std::string>, int>::ok(cookie_string);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

/*
 cookie-header = "Cookie:" OWS cookie-string OWS
 cookie-string = cookie-pair *( ";" SP cookie-pair )

 cookie-pair       = cookie-name "=" cookie-value
 cookie-name       = token
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
                       ; US-ASCII characters excluding CTLs,
                       ; whitespace DQUOTE, comma, semicolon,
                       ; and backslash
 https://tex2e.github.io/rfc-translater/html/rfc6265.html#4-2-1--Syntax
 */
Result<int, int> HttpRequest::set_cookie(const std::string &field_name,
										 const std::string &field_value) {
	std::map<std::string, std::string> cookie_string;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_cookie_string(field_value);
	if (result.is_ok()) {
		cookie_string = result.get_ok_value();
		this->_request_header_fields[field_name] = new MapFieldValues(cookie_string);
	}
	return Result<int, int>::ok(STATUS_OK);
}
