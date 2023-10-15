#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueMap.hpp"

namespace {

/* Cookie */

/*
 cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
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

/*
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 */
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

/*
 cookie-pair       = cookie-name "=" cookie-value
 */
Result<int, int> parse_cookie_pair(const std::string &field_value,
								   std::size_t start_pos,
								   std::size_t *end_pos,
								   std::string *cookie_name,
								   std::string *cookie_value) {
	std::size_t pos, end, len;

	if (!end_pos || !cookie_name || !cookie_value) { return Result<int, int>::err(ERR); }
	if (field_value.empty()) { return Result<int, int>::err(ERR); }

	// cookie-name
	pos = start_pos;
	end = field_value.find('=', pos);
	if (end == std::string::npos) { return Result<int, int>::err(ERR); }
	len = end - pos;
	*cookie_name = field_value.substr(pos, len);
	pos += len;

	// =
	if (field_value[pos] != '=') { return Result<int, int>::err(ERR); }
	++pos;

	// cookie-value
	skip_cookie_value(field_value, pos, &end);
	if (pos == end) { return Result<int, int>::err(ERR); }
	len = end - pos;

	*cookie_value = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<int, int>::ok(OK);
}

/*
 cookie-string = cookie-pair *( ";" SP cookie-pair )
 cookie-pair   = cookie-name "=" cookie-value
 */
Result<std::map<std::string, std::string>, int> parse_cookie_string(const std::string &field_value) {
	Result<int, int> parse_result;
	std::string cookie_name, cookie_value;
	std::map<std::string, std::string> cookie_string;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (field_value[pos]) {
		parse_result = parse_cookie_pair(field_value, pos, &end,
										 &cookie_name, &cookie_value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		cookie_string[cookie_name] = cookie_value;
		pos = end;

		if (field_value[pos] == '\0') { break; }
		if (field_value[pos] == ';'
			&& field_value[pos + 1] == SP
			&& field_value[pos + 2] != '\0') {
			pos += 3;
			continue;
		}
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(cookie_string);
}

/*
 cookie-name       = token
 */
bool is_valid_cookie_name(const std::string &cookie_name) {
	return HttpMessageParser::is_token(cookie_name);
}

/*
 cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
 */
bool is_valid_cookie_value(const std::string &cookie_value) {
	std::size_t pos, end;

	if (cookie_value.empty()) { return false; }

	pos = 0;
	skip_cookie_value(cookie_value, pos, &end);
	if (pos == end) { return false; }
	return cookie_value[end] == '\0';
}

Result<int, int> validate_cookie_string(const std::map<std::string, std::string> &cookie_string) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string cookie_name, cookie_value;

	if (cookie_string.empty()) { return Result<int, int>::err(ERR); }

	for (itr = cookie_string.begin(); itr != cookie_string.end(); ++itr) {
		cookie_name = itr->first;
		cookie_value = itr->second;

		if (!is_valid_cookie_name(cookie_name)) {
			return Result<int, int>::err(ERR);
		}
		if (!is_valid_cookie_value(cookie_value)) {
			return Result<int, int>::err(ERR);
		}
	}
	return Result<int, int>::ok(OK);
}


Result<std::map<std::string, std::string>, int> parse_and_validate_cookie_string(
		const std::string &field_value) {
	std::map<std::string, std::string> cookie_string;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	parse_result = parse_cookie_string(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	cookie_string = parse_result.get_ok_value();

	validate_result = validate_cookie_string(cookie_string);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
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
		this->_request_header_fields[field_name] = new FieldValueMap(cookie_string);
	}
	return Result<int, int>::ok(STATUS_OK);
}
