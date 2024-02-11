#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

namespace {

std::size_t get_value_len(const std::string &str, char separator, char delimiter) {
	std::size_t len;

	len = 0;
	while (str[len]) {
		if (str[len] == delimiter) {
			break;
		}
		len++;
	}
	while (len > 0 && str[len - 1] == separator) {
		len--;
	}
	return len;
}

void skip_ows_delim_ows(const std::string &str, char delimiter, std::size_t *pos) {
	while (str[*pos] == SP) { *pos += 1; }
	if (str[*pos] == delimiter) { *pos += 1; }
	while (str[*pos] == SP) { *pos += 1; }
}

// field_value = [ value *( OWS "," OWS value ) ]
// field_value = [ value *( SEPARATOR DELIMITER SEPARATOR value ) ] <- todo
std::set<std::string> parse_field_values(const std::string &field_value) {
	std::size_t pos, len;
	std::string value;
	std::set<std::string> field_values;

	pos = 0;
	while (field_value[pos]) {
		len = get_value_len(&field_value[pos], SP, COMMA);
		value = field_value.substr(pos, len);
		field_values.insert(value);
		pos += len;
		if (field_value[pos] == '\0' || len == 0) {
			break;
		}

		skip_ows_delim_ows(field_value, COMMA, &pos);

		if (field_value[pos] == '\0') {
			field_values.insert(std::string(EMPTY));
		}
	}
	return field_values;
}

bool is_valid_field_values(const std::set<std::string> &field_values,
						   bool (*is_valid_syntax)(const std::string &)) {
	std::set<std::string>::const_iterator itr;

	for (itr = field_values.begin(); itr != field_values.end(); ++itr) {
		if (!is_valid_syntax(*itr)) {
			return false;
		}
	}
	return true;
}

/*
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )

 quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
 qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
 quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
 */
void skip_transfer_parameter(const std::string &str,
							 std::size_t *pos,
							 bool *succeed) {
	std::size_t end_pos;

	if (!succeed || !pos) { return; }

	*succeed = false;
	if (str.empty() || str.length() < *pos) { return; }

	// token
	if (!HttpMessageParser::is_tchar(str[*pos])) { return; }
	while (HttpMessageParser::is_tchar(str[*pos])) { *pos += 1; }

	// BWS
	HttpMessageParser::skip_ows(str, &*pos);

	// '='
	if (str[*pos] != EQUAL_SIGN) { return; }
	*pos += 1;

	// BWS
	HttpMessageParser::skip_ows(str, &*pos);

	if (HttpMessageParser::is_tchar(str[*pos])) {
		// token
		while (str[*pos] && HttpMessageParser::is_tchar(str[*pos])) {
			*pos += 1;
		}
	} else if (str[*pos] == '"') {
		HttpMessageParser::skip_quoted_string(str, *pos, &end_pos);
		if (*pos == end_pos) { return; }
		*pos = end_pos;
	} else { return; }  // error
	*succeed = true;
}

/*
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )

  Transfer-Encoding
  = [ transfer-coding *( OWS "," OWS transfer-coding ) ]
  = [ token *( OWS ";" OWS transfer-parameter ) *( OWS "," OWS token *( OWS ";" OWS transfer-parameter ) )
 */
bool is_transfer_coding(const std::string &str) {
	std::size_t pos;
	bool		succeed;

	if (str.empty()) {
		return false;
	}

	pos = 0;
	// token
	while (HttpMessageParser::is_tchar(str[pos])) { pos++; }

	if (str[pos] == '\0') {
		return true;
	}

	// *( OWS ";" OWS transfer-parameter )
	while (str[pos]) {
		HttpMessageParser::skip_ows(str, &pos);
		if (str[pos] != SEMICOLON) {
			return false;
		}
		pos++;

		HttpMessageParser::skip_ows(str, &pos);
		if (str[pos] == '\0') {
			return false;
		}

		skip_transfer_parameter(str, &pos, &succeed);
		if (!succeed) {
			return false;
		}
	}
	return str[pos] == '\0';
}

//------------------------------------------------------------------------------
/* Origin */

std::string get_serialized_origin_str(const std::string &scheme,
									  const std::string &host,
									  const std::string &port) {
	std::string origin;

	origin.append(scheme);
	origin.append("://");
	origin.append(host);
	origin.append(port.empty() ? "" : ":" + port);
	return origin;
}

Result<int, int> parse_serialized_origin(const std::string &field_value,
										 std::size_t start_pos,
										 std::size_t *end_pos,
										 std::string *scheme,
										 std::string *host,
										 std::string *port) {
	std::size_t pos, end, len;
	Result<std::string, int> host_result, port_result;

	if (!end_pos || !scheme || !host || !port) {
		return Result<int, int>::err(ERR);
	}
	pos = start_pos;
	*end_pos = start_pos;
	*scheme = std::string(EMPTY);
	*host = std::string(EMPTY);
	*port = std::string(EMPTY);
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<int, int>::err(ERR);
	}

	// scheme
	end = field_value.find(':', pos);
	if (end == std::string::npos) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*scheme = field_value.substr(pos, len);
	pos += len;

	// "://"
	if (!(field_value[pos] == ':'
		  && field_value[pos + 1] == '/'
		  && field_value[pos + 2] == '/')) {
		return Result<int, int>::err(ERR);
	}
	pos += std::string("://").length();

	// host
	host_result = HttpMessageParser::parse_uri_host(field_value, pos, &end);
	if (host_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*host = host_result.get_ok_value();
	pos = end;

	// ":"
	if (field_value[pos] != ':') {
		*end_pos = end;
		return Result<int, int>::ok(OK);
	}
	++pos;

	// port
	port_result = HttpMessageParser::parse_port(field_value, pos, &end);
	if (port_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*port = port_result.get_ok_value();

	*end_pos = end;
	return Result<int, int>::ok(OK);
}

Result<int, int> validate_serialized_oritin(const std::string &scheme,
											const std::string &host,
											const std::string &port) {
	if (!HttpMessageParser::is_scheme(scheme)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_uri_host(host)) {
		return Result<int, int>::err(ERR);
	}
	if (!port.empty() && !HttpMessageParser::is_port(port)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

/*
 origin-list         = serialized-origin *( SP serialized-origin )
 serialized-origin   = scheme "://" host [ ":" port ]
                     ; <scheme>, <host>, <port> from RFC 3986
 scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 */
Result<std::set<std::string>, int> parse_and_validate_origin_list(const std::string &field_value) {
	std::set<std::string> origin_set;
	std::string scheme, host, port, serialized_origin;
	std::size_t pos, end;
	Result<int, int> parse_result, validate_result;

	if (field_value.empty()) {
		return Result<std::set<std::string>, int>::err(ERR);
	}
	pos = 0;
	while (field_value[pos]) {
		parse_result = parse_serialized_origin(field_value,
											   pos, &end,
											   &scheme, &host, &port);

		if (parse_result.is_err()) {
			return Result<std::set<std::string>, int>::err(ERR);
		}

		validate_result = validate_serialized_oritin(scheme, host, port);
		if (validate_result.is_err()) {
			return Result<std::set<std::string>, int>::err(ERR);
		}

		serialized_origin = get_serialized_origin_str(scheme, host, port);
		origin_set.insert(serialized_origin);

		pos = end;
		if (field_value[pos] == SP && field_value[pos + 1] != '\0') {
			++pos;
			continue;
		}
	}
	return Result<std::set<std::string>, int>::ok(origin_set);
}

Result<std::set<std::string>, int>
parse_and_validate_origin_list_or_null(const std::string &field_value) {
	Result<std::set<std::string>, int> result;
	std::set<std::string> origin_set;

	if (field_value == "null") {
		origin_set.insert(field_value);
		return Result<std::set<std::string>, int>::ok(origin_set);
	}

	result = parse_and_validate_origin_list(field_value);
	if (result.is_err()) {
		return Result<std::set<std::string>, int>::err(ERR);
	}
	origin_set = result.get_ok_value();
	return Result<std::set<std::string>, int>::ok(origin_set);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Result<int, int> HttpRequest::set_multi_field_values(const std::string &field_name,
													 const std::string &field_value,
													 bool (*syntax_validate_func)(const std::string &)) {
	std::set<std::string> field_values;

	field_values = parse_field_values(field_value);
	if (is_valid_field_values(field_values, syntax_validate_func)) {
		this->request_header_fields_[field_name] = new MultiFieldValues(field_values);
	}
	return Result<int, int>::ok(STATUS_OK);
}

////////////////////////////////////////////////////////////////////////////////

// Access-Control-Request-Headers: <header-name>, <header-name>, ...
/*
 Access-Control-Request-Headers: "Access-Control-Request-Headers" ":" #field-name
 */
// field-name *( OWS "," OWS field-name )
Result<int, int> HttpRequest::set_access_control_request_headers(const std::string &field_name,
																 const std::string &field_value) {
	std::string lower_field_value;

	clear_field_values_of(field_name);
	lower_field_value = StringHandler::to_lower(field_value);
	return set_multi_field_values(field_name,
								  lower_field_value,
								  HttpMessageParser::is_valid_field_name);
}

// Content-Encoding = [ content-coding *( OWS "," OWS content-coding )
// content-coding   = token
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
Result<int, int> HttpRequest::set_content_encoding(const std::string &field_name,
												   const std::string &field_value) {
	clear_field_values_of(field_name);
	return set_multi_field_values(field_name,
								  field_value,
								  HttpMessageParser::is_token);
}

// Content-Language = [ language-tag *( OWS "," OWS language-tag ) ]
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
Result<int, int> HttpRequest::set_content_language(const std::string &field_name,
												   const std::string &field_value) {
	clear_field_values_of(field_name);
	return set_multi_field_values(field_name,
								  field_value,
								  HttpMessageParser::is_language_tag);
}

/*
 If-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
Result<int, int> HttpRequest::set_if_match(const std::string &field_name,
										   const std::string &field_value) {
	if (is_field_name_repeated_in_request(field_name)) {
		clear_field_values_of(field_name);
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	if (field_value == "*") {
		return set_multi_field_values(field_name,
									  field_value,
									  HttpMessageParser::is_token);
	} else {
		return set_multi_field_values(field_name,
									  field_value,
									  HttpMessageParser::is_entity_tag);
	}
}

/*
 If-None-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
Result<int, int> HttpRequest::set_if_none_match(const std::string &field_name,
												const std::string &field_value) {
	if (is_field_name_repeated_in_request(field_name)) {
		clear_field_values_of(field_name);
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	if (field_value == "*") {
		return set_multi_field_values(field_name,
									  field_value,
									  HttpMessageParser::is_token);
	} else {
		return set_multi_field_values(field_name,
									  field_value,
									  HttpMessageParser::is_entity_tag);
	}
}

// Origin: null
// Origin: <scheme>://<hostname>
// Origin: <scheme>://<hostname>:<port>
/*
 origin              = "Origin:" OWS origin-list-or-null OWS
 origin-list-or-null = %x6E %x75 %x6C %x6C / origin-list
 origin-list         = serialized-origin *( SP serialized-origin )
 serialized-origin   = scheme "://" host [ ":" port ]
                     ; <scheme>, <host>, <port> from RFC 3986
 https://www.rfc-editor.org/rfc/rfc6454#section-7

 scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
 https://www.rfc-editor.org/rfc/rfc3986#section-3.1
 */
Result<int, int> HttpRequest::set_origin(const std::string &field_name,
										 const std::string &field_value) {
	std::set<std::string> origin_set_or_null;
	Result<std::set<std::string>, int> result;

	clear_field_values_of(field_name);

	result = parse_and_validate_origin_list_or_null(field_value);
	if (result.is_err()) {
		return Result<int, int>::ok(STATUS_OK);
	}
	origin_set_or_null = result.get_ok_value();

	this->request_header_fields_[field_name] = new MultiFieldValues(origin_set_or_null);
	return Result<int, int>::ok(STATUS_OK);
}

/*
 Transfer-Encoding = [ transfer-coding *( OWS "," OWS transfer-coding ) ]
 */
Result<int, int> HttpRequest::set_transfer_encoding(const std::string &field_name,
													const std::string &field_value) {
	if (is_field_name_repeated_in_request(field_name)) {
		clear_field_values_of(field_name);
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	return set_multi_field_values(field_name,
								  field_value,
								  is_transfer_coding);
}
