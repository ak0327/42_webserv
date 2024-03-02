#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapSetFieldValues.hpp"

namespace {

// link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
Result<int, int> parse_uri_reference(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos,
									 std::string *uri_reference) {
	std::size_t pos, end, len;
	Result<int, int> uri_reference_result, link_param_result;

	if (!end_pos || !uri_reference) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}
	pos = start_pos;
	if (field_value[pos] != '<') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	end = field_value.find('>', pos);
	if (end == std::string::npos) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*uri_reference = field_value.substr(pos, len);
	pos += len + 1;
	*end_pos = pos;
	return Result<int, int>::ok(OK);
}

// link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
Result<int, int> parse_link_param(const std::string &field_value,
								  std::size_t start_pos,
								  std::size_t *end_pos,
								  std::string *link_param_key,
								  std::string *link_param_value) {
	std::size_t pos, end, len;

	if (!end_pos) {
		return Result<int, int>::err(ERR);
	}

	*end_pos = start_pos;
	*link_param_key = std::string(EMPTY);
	*link_param_value = std::string(EMPTY);
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}
	pos = start_pos;

	// token
	len = 0;
	while (field_value[pos + len]
	&& !HttpMessageParser::is_whitespace(field_value[pos + len])
	&& field_value[pos + len] != EQUAL_SIGN
	&& field_value[pos + len] != COMMA) {
		++len;
	}
	if (len == 0) {
		return Result<int, int>::err(ERR);
	}
	*link_param_key = field_value.substr(pos, len);
	pos += len;

	// BWS
	HttpMessageParser::skip_ows(field_value, &pos);
	*end_pos = pos;

	// [ "=" BWS ( token / quoted-string ) ]
	if (field_value[pos] != EQUAL_SIGN) {
		return Result<int, int>::ok(OK);
	}
	++pos;
	HttpMessageParser::skip_ows(field_value, &pos);

	if (HttpMessageParser::is_tchar(field_value[pos])) {
		HttpMessageParser::skip_token(field_value, pos, &end);
	} else if (field_value[pos] == DOUBLE_QUOTE) {
		HttpMessageParser::skip_quoted_string(field_value, pos, &end);
	} else {
		return Result<int, int>::err(ERR);
	}

	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*link_param_value = field_value.substr(pos, len);

	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

/*
 link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
 link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
 */
Result<std::map<std::string, std::string>, int> parse_link_value(const std::string &field_value,
																 std::size_t start_pos,
																 std::size_t *end_pos) {
	std::size_t pos, end;
	std::map<std::string, std::string> link_value;
	std::string uri_reference, link_param_key, link_param_value;
	Result<int, int> uri_reference_result, link_param_result;

	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	// "<" URI-Reference ">"
	pos = start_pos;
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	uri_reference_result = parse_uri_reference(field_value,
											   pos, &end,
											   &uri_reference);
	if (uri_reference_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	link_value[std::string(URI_REFERENCE)] = uri_reference;
	pos = end;

	// *( OWS ";" OWS link-param )
	while (field_value[pos] && field_value[pos] != COMMA) {  // delimiter of #link-value
		HttpMessageParser::skip_ows(field_value, &pos);
		if (field_value[pos] != SEMICOLON) {
			break;
		}
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);

		link_param_result = parse_link_param(field_value,
											 pos, &end,
											 &link_param_key, &link_param_value);
		if (link_param_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}

		link_value[link_param_key] = link_param_value;
		pos = end;
	}
	*end_pos = pos;
	return Result<std::map<std::string, std::string>, int>::ok(link_value);
}

// URI = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
bool is_uri(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;

	if (str[pos] != COLON) {
		return false;
	}
	++pos;

	HttpMessageParser::skip_hier_part(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;

	if (str[pos] == '?') {
		++pos;
		HttpMessageParser::skip_query(str, pos, &end);
		pos = end;
	}
	if (str[pos] == '#') {
		++pos;
		HttpMessageParser::skip_fragment(str, pos, &end);
		pos = end;
	}
	return str[pos] == '\0';
}

// relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
bool is_relative_ref(const std::string &str) {
	std::size_t pos, end;

	if (str.empty()) {
		return false;
	}
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	if (pos == end) {
		return false;
	}
	pos = end;

	if (str[pos] == '?') {
		++pos;
		HttpMessageParser::skip_query(str, pos, &end);
		pos = end;
	}
	if (str[pos] == '#') {
		++pos;
		HttpMessageParser::skip_fragment(str, pos, &end);
		pos = end;
	}
	return str[pos] == '\0';
}

// URI-reference = URI / relative-ref
bool is_valid_uri_reference(const std::string &uri_reference) {
	return (is_uri(uri_reference) || is_relative_ref(uri_reference));
}

bool is_valid_link_param_key(const std::string &link_param_key) {
	return HttpMessageParser::is_token(link_param_key);
}

bool is_valid_link_param_value(const std::string &link_param_value) {
	if (link_param_value.empty()) {
		return true;
	}
	return (HttpMessageParser::is_token(link_param_value)
			|| HttpMessageParser::is_quoted_string(link_param_value));
}

bool has_key(const std::map<std::string, std::string> &map,
				  const std::string &key) {
	return map.find(key) != map.end();
}

/*
 link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
 link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
 */
Result<int, int> validate_link_value(const std::map<std::string, std::string> &link_value) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;
	bool is_valid_key, is_valid_value;

	if (link_value.empty()) {
		return Result<int, int>::err(ERR);
	}
	if (!has_key(link_value, std::string(URI_REFERENCE))) {
		return Result<int, int>::err(ERR);
	}

	for (itr = link_value.begin(); itr != link_value.end(); ++itr) {
		 key = itr->first;
		 value = itr->second;

		 if (key == URI_REFERENCE) {
			 is_valid_key = true;
			 is_valid_value = is_valid_uri_reference(value);
		 } else {
			 is_valid_key = is_valid_link_param_key(key);
			 is_valid_value = is_valid_link_param_value(value);
		 }

		 if (is_valid_key && is_valid_value) {
			 continue;
		 }
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

/*
 Link       = #link-value
 link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
 link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
 */
Result<std::map<std::string, std::string>, int>
parse_and_validate_link_value(const std::string &field_value,
							 std::size_t start_pos,
							 std::size_t *end_pos) {
	std::map<std::string, std::string> link_value;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result;

	parse_result = parse_link_value(field_value, start_pos, end_pos);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	link_value = parse_result.ok_value();

	validate_result = validate_link_value(link_value);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	return Result<std::map<std::string, std::string>, int>::ok(link_value);
}


}  // namespace

/*
 Link       = #link-value
 link-value = "<" URI-Reference ">" *( OWS ";" OWS link-param )
 link-param = token BWS [ "=" BWS ( token / quoted-string ) ]
 https://httpwg.org/specs/rfc8288.html#header

 1#element => element *( OWS "," OWS element )

 URI-reference = URI / relative-ref
 URI           = scheme ":" hier-part [ "?" query ] [ "#" fragment ]
 relative-ref  = relative-part [ "?" query ] [ "#" fragment ]
 relative-part = "//" authority path-abempty
                  / path-absolute
                  / path-noscheme
                  / path-empty
 fragment      = *( pchar / "/" / "?" )
 https://www.rfc-editor.org/rfc/rfc3986.html

  std::set<std::map<std::string, std::string> > links = {link1, link2, ... };

  link_i["URI-Reference"] = URI-Reference;
  link_i[token] = token / quoted-string;
 */
Result<int, int> HttpRequest::set_link(const std::string &field_name,
									   const std::string &field_value) {
	Result<std::set<std::map<std::string, std::string> >, int> result;
	std::set<std::map<std::string, std::string> > link_values;

	clear_field_values_of(field_name);

	result = HttpMessageParser::parse_map_set_field_values(field_value,
														   parse_and_validate_link_value);
	if (result.is_err()) {
		return Result<int, int>::ok(STATUS_OK);
	}
	link_values = result.ok_value();

	this->request_header_fields_[field_name] = new MapSetFieldValues(link_values);
	return Result<int, int>::ok(STATUS_OK);
}
