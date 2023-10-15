#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

namespace {

/*
 FIELD_NAME   = #MAP_ELEMENT
 MAP_ELEMENT  = token [ "=" ( token / quoted-string ) ]
 1#element => element *( OWS "," OWS element )
 */
Result<int, int> parse_map_element(const std::string &field_value,
								   std::size_t start_pos,
								   std::size_t *end_pos,
								   std::string *key,
								   std::string *value) {
	std::size_t pos, end, len;

	if (!end_pos || !key || !value) {
		return Result<int, int>::err(ERR);
	}
	if (field_value.empty()) {
		return Result<int, int>::err(ERR);
	}

	// key
	pos = start_pos;
	len = 0;
	while (field_value[pos + len]
		   && HttpMessageParser::is_tchar(field_value[pos + len])) {
		++len;
	}
	*key = field_value.substr(pos, len);
	pos += len;

	// =
	if (field_value[pos] == ELEMENT_SEPARATOR || field_value[pos] == '\0') {
		*value = std::string(EMPTY);
		*end_pos = pos;
		return Result<int, int>::ok(OK);
	}
	if (field_value[pos] != '=') { return Result<int, int>::err(ERR); }
	++pos;

	// value
	len = 0;
	if (std::isdigit(field_value[pos])) {
		while (field_value[pos + len] && std::isdigit(field_value[pos + len])) {
			++len;
		}
	} else if (HttpMessageParser::is_tchar(field_value[pos])) {
		while (field_value[pos + len]
				&& HttpMessageParser::is_tchar(field_value[pos + len])) {
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
	*value = field_value.substr(pos, len);

	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

bool is_key_only(const std::string &value) {
	return value.empty();
}

//------------------------------------------------------------------------------

/* Authorization */
// auth-param    = token BWS "=" BWS ( token / quoted-string )
bool is_auth_param(const std::string &str) {
	std::size_t pos;

	if (str.empty()) { return false; }

	pos = 0;
	while (HttpMessageParser::is_tchar(str[pos])) {
		++pos;
	}
	if (pos == 0) { return false; }

	HttpMessageParser::skip_ows(str, &pos);
	if (str[pos] != '=') { return false; }
	HttpMessageParser::skip_ows(str, &pos);

	return HttpMessageParser::is_token(&str[pos])
		   || HttpMessageParser::is_quoted_string(&str[pos]);
}

// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
//                                     ^^^^^^^^^^^^^^^^^^^^^^ auth_param
bool is_valid_auth_param(const std::string &auth_param) {
	return (HttpMessageParser::is_token68(auth_param)
			|| is_auth_param(auth_param));
}

// auth-scheme   = token
bool is_valid_auth_scheme(const std::string &auth_scheme) {
	return HttpMessageParser::is_token(auth_scheme);
}

Result<int, int> validate_credentials(const std::map<std::string, std::string> &credentials) {
	const std::size_t AUTH_SCHEME_ONLY = 1;
	std::map<std::string, std::string>::const_iterator itr;
	std::string auth_scheme, auth_param;

	itr = credentials.find(std::string(AUTH_SCHEME));
	if (itr == credentials.end()) {
		return Result<int, int>::err(ERR);
	}
	auth_scheme = itr->second;
	if (!is_valid_auth_scheme(auth_scheme)) {
		return Result<int, int>::err(ERR);
	}

	itr = credentials.find(std::string(AUTH_PARAM));
	if (itr == credentials.end()) {
		if (credentials.size() == AUTH_SCHEME_ONLY) {
			return Result<int, int>::ok(OK);
		}
		return Result<int, int>::err(ERR);
	}
	auth_param = itr->second;
	if (!is_valid_auth_param(auth_param)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
// auth-scheme   = token
Result<std::string, int> parse_auth_scheme(const std::string &field_value,
										   std::size_t start_pos,
										   std::size_t *end_pos) {
	std::string auth_scheme;
	std::size_t len;

	if (!end_pos) { return Result<std::string, int>::err(ERR); }
	if (field_value.empty()) { return Result<std::string, int>::err(ERR); }

	len = 0;
	while (HttpMessageParser::is_tchar(field_value[start_pos + len])) {
		++len;
	}
	auth_scheme = field_value.substr(start_pos, len);

	// std::cout << CYAN << "  auth_scheme:[" << auth_scheme << "]" << RESET << std::endl;
	// std::cout << CYAN << "  start_pos:[" << start_pos << "]" << RESET << std::endl;
	// std::cout << CYAN << "  len:[" << len << "]" << RESET << std::endl;

	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(auth_scheme);
}

// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
// auth-param    = token BWS "=" BWS ( token / quoted-string )
// token68       = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
Result<std::string, int> parse_auth_param(const std::string &field_value,
										  std::size_t start_pos,
										  std::size_t *end_pos) {
	std::string auth_param;
	std::size_t pos, len;

	if (!end_pos) { return Result<std::string, int>::err(ERR); }
	if (field_value.empty()) { return Result<std::string, int>::err(ERR); }

	pos = start_pos;
	if (field_value[pos] != SP) { return Result<std::string, int>::err(ERR); }
	++pos;

	auth_param = field_value.substr(pos);
	len = auth_param.length();
	*end_pos = pos + len;
	return Result<std::string, int>::ok(auth_param);
}

// Authorization: <type> <credentials>

// Authorization = credentials
// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
// https://datatracker.ietf.org/doc/html/rfc7235#section-4.2
Result<std::map<std::string, std::string>, int> parse_credentials(const std::string &field_value) {
	std::map<std::string, std::string> credentials;
	std::string auth_scheme, auth_param;
	Result<std::string, int> auth_scheme_result, auth_param_result;
	std::size_t pos, end_pos;

	pos = 0;
	auth_scheme_result = parse_auth_scheme(field_value, pos, &end_pos);
	if (auth_scheme_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	credentials[std::string(AUTH_SCHEME)] = auth_scheme_result.get_ok_value();
	pos = end_pos;

	if (field_value[pos] != '\0') {
		auth_param_result = parse_auth_param(field_value, pos, &end_pos);
		if (auth_param_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		credentials[std::string(AUTH_PARAM)] = auth_param_result.get_ok_value();
	}
	pos = end_pos;

	if (field_value[pos] != '\0') {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(credentials);
}

Result<std::map<std::string, std::string>, int> parse_and_validate_credentials(
												const std::string &field_value) {
	Result<std::map<std::string, std::string> , int> parse_result;
	Result<int, int> validate_result;
	std::map<std::string, std::string> credentials;

	parse_result = parse_credentials(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	credentials = parse_result.get_ok_value();

	validate_result = validate_credentials(credentials);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(credentials);
}

//------------------------------------------------------------------------------
/* Forwarded */

Result<std::string, int> parse_forwarded_value(const std::string &field_value,
											   std::size_t start_pos,
											   std::size_t *end_pos) {
	std::size_t len, end;
	std::string value;

	if (field_value.empty()) {
		return Result<std::string, int>::err(ERR);
	}
	len = 0;
	if (HttpMessageParser::is_tchar(field_value[start_pos])) {
		while (HttpMessageParser::is_tchar(field_value[start_pos + len])) {
			++len;
		}
	} else if (field_value[start_pos] == '"') {
		HttpMessageParser::skip_quoted_string(field_value, start_pos, &end);
		if (start_pos == end) {
			return Result<std::string, int>::err(ERR);
		}
		len = end - start_pos;
	} else {
		return Result<std::string, int>::err(ERR);
	}

	value = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(value);
}

/*
 forwarded-pair = token "=" value
 value          = token / quoted-string
 */
Result<int, int> parse_forwarded_pair(const std::string &field_value,
									  std::size_t start_pos,
									  std::size_t *end_pos,
									  std::string *token,
									  std::string *value) {
	std::size_t pos, end;
	Result<std::string, int> token_result, value_result;

	if (!end_pos || !token || !value) { return Result<int, int>::err(ERR); }

	pos = start_pos;
	token_result = StringHandler::parse_pos_to_delimiter(field_value,
														 pos, '=', &end);
	if (token_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*token = token_result.get_ok_value();
	pos = end;

	if (field_value[pos] != '=') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	value_result = parse_forwarded_value(field_value, pos, &end);
	if (value_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*value = value_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

/*
 forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
 */
Result<std::map<std::string, std::string>, int> parse_and_validate_forwarded_element(
													const std::string &field_value) {
	std::map<std::string, std::string> forwarded_element;
	Result<int, int> parse_result, validate_result;
	std::string token, value;
	std::size_t pos, end_pos;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (true) {
		parse_result = parse_forwarded_pair(field_value, pos, &end_pos, &token, &value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end_pos;
		forwarded_element[token] = value;

		if (field_value[pos] == '\0') {
			break;
		} else if (field_value[pos] == ';' && field_value[pos + 1] != '\0') {
			++pos;
		} else {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
	}
	return Result<std::map<std::string, std::string>, int>::ok(forwarded_element);
}

//------------------------------------------------------------------------------
/* Keep-Alive */

Result<std::map<std::string, std::string>, int> parse_keep_alive_info(const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<int, int> parse_result;
	std::string key, value;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (true) {
		parse_result = parse_map_element(field_value, pos, &end, &key, &value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end;
		keep_alive_info[key] = value;

		if (field_value[pos] == '\0') { break; }

		HttpMessageParser::skip_ows(field_value, &pos);
		if (field_value[pos] != ELEMENT_SEPARATOR) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);

		if (field_value[pos] == '\0') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
	}

	return Result<std::map<std::string, std::string>, int>::ok(keep_alive_info);
}

Result<int, int> validate_keep_alive_info(const std::map<std::string, std::string> &keep_alive_info) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;
	bool succeed;

	if (keep_alive_info.empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = keep_alive_info.begin(); itr != keep_alive_info.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (key == std::string(TIMEOUT)) {
			HttpMessageParser::to_delta_seconds(value, &succeed);
			if (succeed) { continue; }
		} else if (HttpMessageParser::is_token(key)) {
			if (is_key_only(value)) { continue; }
			if (HttpMessageParser::is_token(value)) { continue; }
			if (HttpMessageParser::is_quoted_string(value)) { continue; }
		}
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

Result<int, int> reformat_delta_seconds(std::map<std::string, std::string> *keep_alive_info) {
	std::map<std::string, std::string>::iterator itr;
	std::string key, value;
	int delta_seconds;
	bool succeed;

	if (!keep_alive_info || keep_alive_info->empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = keep_alive_info->begin(); itr != keep_alive_info->end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (key != std::string(TIMEOUT)) { continue; }

		delta_seconds = HttpMessageParser::to_delta_seconds(value, &succeed);
		if (!succeed) {
			return Result<int, int>::err(ERR);
		}
		itr->second = StringHandler::to_string(delta_seconds);
	}

	return Result<int, int>::ok(OK);
}

/*
 keep-alive-info      =   "timeout" "=" delta-seconds
                        / keep-alive-extension
 keep-alive-extension = token [ "=" ( token / quoted-string ) ]
 https://datatracker.ietf.org/doc/html/draft-thomson-hybi-http-timeout-03#section-2

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension

 */
Result<std::map<std::string, std::string>, int> parse_and_validate_keep_alive_info(
		const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result, reformat_result;

	parse_result = parse_keep_alive_info(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	keep_alive_info = parse_result.get_ok_value();

	validate_result = validate_keep_alive_info(keep_alive_info);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	reformat_result = reformat_delta_seconds(&keep_alive_info);
	if (reformat_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	return Result<std::map<std::string, std::string>, int>::ok(keep_alive_info);
}

//------------------------------------------------------------------------------
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

//------------------------------------------------------------------------------
/* Cache-Control */

/*
 Cache-Control   = #cache-directive
 cache-directive = token [ "=" ( token / quoted-string ) ]
 https://www.rfc-editor.org/rfc/rfc9111#field.cache-control

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
Result<std::map<std::string, std::string> , int> parse_cache_directive(
		const std::string &field_value) {
	std::map<std::string, std::string> cache_directive;
	Result<int, int> parse_result;
	std::string key, value;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (true) {
		parse_result = parse_map_element(field_value, pos, &end, &key, &value);
		if (parse_result.is_err()) {
			std::cout << YELLOW << "2" << RESET << std::endl;
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end;
		cache_directive[key] = value;

		if (field_value[pos] == '\0') { break; }

		HttpMessageParser::skip_ows(field_value, &pos);
		if (field_value[pos] != ELEMENT_SEPARATOR) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);

		if (field_value[pos] == '\0') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
	}

	return Result<std::map<std::string, std::string>, int>::ok(cache_directive);
}

/*
 cache-directive = token [ "=" ( token / quoted-string ) ]
 */
Result<int, int> validate_cache_directive(
		const std::map<std::string, std::string> &cache_directive) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;

	if (cache_directive.empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = cache_directive.begin(); itr != cache_directive.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		std::cout << "key:[" << key << "], value:[" << value << "]" << std::endl;

		if (!HttpMessageParser::is_token(key)) {
			return Result<int, int>::err(ERR);
		}

		if (is_key_only(value)) { continue; }
		if (HttpMessageParser::is_token(value)) {
			std::cout << CYAN << " token ok" << RESET << std::endl;
			continue; }
		if (HttpMessageParser::is_quoted_string(value)) {
			std::cout << CYAN << " quoted ok" << RESET << std::endl;
			continue; }

		return Result<int, int>:: err(ERR);
	}

	return Result<int, int>::ok(OK);
}

Result<std::map<std::string, std::string>, int> parse_and_validate_cache_directive(
		const std::string &field_value) {
	Result<std::map<std::string, std::string> , int> parse_result;
	Result<int, int> validate_result;
	std::map<std::string, std::string> cache_directive;

	parse_result = parse_cache_directive(field_value);
	if (parse_result.is_err()) {
		std::cout << CYAN << "parse ng" << RESET << std::endl;
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	std::cout << CYAN << "parse ok" << RESET << std::endl;
	cache_directive = parse_result.get_ok_value();

	validate_result = validate_cache_directive(cache_directive);
	if (validate_result.is_err()) {
		std::cout << CYAN << "validate ng" << RESET << std::endl;
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	std::cout << CYAN << "validate ok" << RESET << std::endl;
	return Result<std::map<std::string, std::string>, int>::ok(cache_directive);
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------


}  // namespace

////////////////////////////////////////////////////////////////////////////////

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &field_value, char delimiter) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(field_value);
	std::string							line;

	while(std::getline(ss, line, delimiter))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new FieldValueMap(value_map));
}

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &field_value) {
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(field_value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[StringHandler::obtain_word_before_delimiter(StringHandler::obtain_withoutows_value(line), '=')] \
		= StringHandler::obtain_word_after_delimiter(StringHandler::obtain_withoutows_value(line), '=');
	return (new FieldValueMap(value_map));
}

FieldValueMap* HttpRequest::ready_ValueMap(const std::string &only_value, const std::string &field_value) {
	std::map<std::string, std::string>	value_map;
	std::stringstream					ss(field_value);
	std::string							line;
	std::string							skipping_word;

	while(std::getline(ss, line, ';'))
	{
		skipping_word = StringHandler::obtain_withoutows_value(line);
		value_map[StringHandler::obtain_word_before_delimiter(skipping_word, '=')] \
		= StringHandler::obtain_withoutows_value(StringHandler::obtain_word_after_delimiter(skipping_word, '='));
	}
	return (new FieldValueMap(only_value, value_map));
}

// Authorization: <type> <credentials>

// Authorization = credentials
// credentials   = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
// auth-scheme   = token
// auth-param    = token BWS "=" BWS ( token / quoted-string )
// token68       = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
// https://datatracker.ietf.org/doc/html/rfc7235#section-4.2
Result<int, int> HttpRequest::set_authorization(const std::string &field_name,
												const std::string &field_value) {
	std::map<std::string, std::string> credentials;
	Result<std::map<std::string, std::string>, int> result;

	if (is_field_name_repeated_in_request(field_name)) {
		clear_field_values_of(field_name);
		return Result<int, int>::err(ERR);
	}

	result = parse_and_validate_credentials(field_value);
	if (result.is_ok()) {
		credentials = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(credentials);
	}
	return Result<int, int>::ok(STATUS_OK);
}

/*
 Cache-Control   = #cache-directive
 cache-directive = token [ "=" ( token / quoted-string ) ]
 https://www.rfc-editor.org/rfc/rfc9111#field.cache-control
 */
Result<int, int> HttpRequest::set_cache_control(const std::string &field_name,
												const std::string &field_value) {

	std::map<std::string, std::string> cache_directive;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_cache_directive(field_value);
	if (result.is_ok()) {
		cache_directive = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(cache_directive);
	}
	return Result<int, int>::ok(STATUS_OK);
}


// 複数OK
// todo: Content-Disposition
// bnf??
Result<int, int> HttpRequest::set_content_disposition(const std::string &field_name,
													  const std::string &field_value) {
	std::stringstream	ss(field_value);
	std::string			only_value;
	std::string			except_onlyvalue_line;
	std::string 		line;

	std::getline(ss, only_value, ';');
	while (std::getline(ss, line, ';'))
		except_onlyvalue_line = except_onlyvalue_line + line;
	_request_header_fields[field_name] = this->ready_ValueMap(only_value,
															  except_onlyvalue_line);
	return Result<int, int>::ok(STATUS_OK);
}

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

/*
 Forwarded   = 1#forwarded-element
 forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
 https://www.rfc-editor.org/rfc/rfc7239#section-4
 */
Result<int, int> HttpRequest::set_forwarded(const std::string &field_name,
											const std::string &field_value) {
	std::map<std::string, std::string> forwarded_element;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_forwarded_element(field_value);
	if (result.is_ok()) {
		forwarded_element = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(forwarded_element);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Host
// Host: <host>:<port>

/*
 Host = uri-host [ ":" port ]
 uri-host = IP-literal / IPv4address / reg-name
 IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
 IPvFuture  = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )

      IPv6address =                            6( h16 ":" ) ls32
                  /                       "::" 5( h16 ":" ) ls32
                  / [               h16 ] "::" 4( h16 ":" ) ls32
                  / [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
                  / [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
                  / [ *3( h16 ":" ) h16 ] "::"    h16 ":"   ls32
                  / [ *4( h16 ":" ) h16 ] "::"              ls32
                  / [ *5( h16 ":" ) h16 ] "::"              h16
                  / [ *6( h16 ":" ) h16 ] "::"

      ls32        = ( h16 ":" h16 ) / IPv4address
                  ; least-significant 32 bits of address

      h16         = 1*4HEXDIG
                  ; 16 bits of address represented in hexadecimal

      IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet

      dec-octet   = DIGIT                 ; 0-9
                  / %x31-39 DIGIT         ; 10-99
                  / "1" 2DIGIT            ; 100-199
                  / "2" %x30-34 DIGIT     ; 200-249
                  / "25" %x30-35          ; 250-255

 reg-name    = *( unreserved / pct-encoded / sub-delims )
 unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
 pct-encoded   = "%" HEXDIG HEXDIG
 sub-delims    = "!" / "$" / "&" / "'" / "(" / ")" / "*" / "+" / "," / ";" / "="

 port          = *DIGIT

https://datatracker.ietf.org/doc/html/rfc3986#appendix-A
 */

// 0 <= port <= 65535
Result<int, int> HttpRequest::set_host(const std::string &field_name,
									   const std::string &field_value)
{
	// std::string	first_value;
	// std::string	second_value;

	if (std::count(field_value.begin(), field_value.end(), ':') == 1)
	{
		std::string	first_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_before_delimiter(field_value, ':'));
		std::string	second_value = HttpMessageParser::obtain_withoutows_value(HttpMessageParser::obtain_word_after_delimiter(field_value, ':'));
		if (first_value == "" || second_value == "")
		{
			this->_status_code = 400;
			return Result<int, int>::err(STATUS_BAD_REQUEST);
		}
	}
	else if (std::count(field_value.begin(), field_value.end(), ':') > 1)
	{
		this->_status_code = 400;
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}
	this->_request_header_fields[field_name] = this->ready_TwoValueSet(field_value, ':');
	return Result<int, int>::ok(STATUS_OK);
}

/*
 Keep-Alive           = "Keep-Alive" ":" 1#keep-alive-info
 https://datatracker.ietf.org/doc/html/draft-thomson-hybi-http-timeout-03#section-2

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
Result<int, int> HttpRequest::set_keep_alive(const std::string &field_name,
											 const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);
	result = parse_and_validate_keep_alive_info(field_value);
	if (result.is_ok()) {
		keep_alive_info = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(keep_alive_info);
	}
	return Result<int, int>::ok(STATUS_OK);
}

/*
 Proxy-Authorization = credentials
 credentials = auth-scheme [ 1*SP ( token68 / #auth-param ) ]
 https://httpwg.org/specs/rfc9110.html#field.proxy-authorization
 */
Result<int, int> HttpRequest::set_proxy_authorization(const std::string &field_name,
													  const std::string &field_value) {
	std::map<std::string, std::string> credentials;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_credentials(field_value);
	if (result.is_ok()) {
		credentials = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(credentials);
	}
	return Result<int, int>::ok(STATUS_OK);
}
