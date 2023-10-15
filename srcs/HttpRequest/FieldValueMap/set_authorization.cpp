#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

namespace {

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
Result<std::map<std::string, std::string>, int> parse_credentials(
		const std::string &field_value) {
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

}  // namespace

////////////////////////////////////////////////////////////////////////////////

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
