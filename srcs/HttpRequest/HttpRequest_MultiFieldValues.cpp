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
		// std::cout << "3 &field_value[pos]: [" << &field_value[pos] << "], value:[" << value << "], len:[" << len << "]" << std::endl;
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

	if (!succeed) { return; }

	*succeed = false;

	// token
	if (!HttpMessageParser::is_tchar(str[*pos])) { return; }
	while (HttpMessageParser::is_tchar(str[*pos])) { *pos += 1; }

	// BWS
	HttpMessageParser::skip_ows(str, &*pos);

	// '='
	if (str[*pos] != '=') { return; }
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

}  // namespace

////////////////////////////////////////////////////////////////////////////////

MultiFieldValues* HttpRequest::ready_ValueArraySet(const std::string &all_value)
{
	std::set<std::string>	value_array;
	std::stringstream			ss(all_value);
	std::string					line;

	while(std::getline(ss, line, ','))
		value_array.insert(HttpMessageParser::obtain_withoutows_value(line));
	return (new MultiFieldValues(value_array));
}

// todo: Access-Control-Request-Headers
// Access-Control-Request-Headers: <header-name>, <header-name>, ...
/*
 Access-Control-Request-Headers: "Access-Control-Request-Headers" ":" #field-name
 */
// todo: bnf ????
Result<int, int> HttpRequest::set_access_control_request_headers(const std::string &field_name,
																 const std::string &field_value)
{
	std::set<std::string>	value_array;
	std::stringstream			ss(field_value);
	std::string					line;
	std::string					word;

	while(std::getline(ss, line, ','))
	{
		if (this->is_valid_field_name(
				HttpMessageParser::obtain_withoutows_value(line)) == false)
			// return;
			return Result<int, int>::ok(STATUS_OK);
	}
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

Result<int, int> HttpRequest::set_multi_field_values(const std::string &field_name,
													 const std::string &field_value,
													 bool (*is_valid_syntax)(const std::string &)) {
	std::set<std::string> field_values;

	field_values = parse_field_values(field_value);
	if (is_valid_field_values(field_values, is_valid_syntax)) {
		this->_request_header_fields[field_name] = new MultiFieldValues(field_values);
	}
	return Result<int, int>::ok(STATUS_OK);
}

// Content-Encoding = [ content-coding *( OWS "," OWS content-coding )
// content-coding   = token
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
Result<int, int> HttpRequest::set_content_encoding(const std::string &field_name,
												   const std::string &field_value) {
	clear_field_values_of(field_name);
	return set_multi_field_values(field_name, field_value, HttpMessageParser::is_token);
}

// todo: Content-Language
// Content-Language = [ language-tag *( OWS "," OWS language-tag ) ]
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
Result<int, int> HttpRequest::set_content_language(const std::string &field_name,
												   const std::string &field_value) {
	clear_field_values_of(field_name);
	return set_multi_field_values(field_name, field_value, HttpMessageParser::is_language_tag);
}

/*
 If-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
Result<int, int> HttpRequest::set_if_match(const std::string &field_name,
										   const std::string &field_value) {
	if (has_multiple_field_names(field_name)) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	if (field_value == "*") {
		return set_multi_field_values(field_name, field_value, HttpMessageParser::is_token);
	} else {
		return set_multi_field_values(field_name, field_value, HttpMessageParser::is_entity_tag);
	}
}

/*
 If-None-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
Result<int, int> HttpRequest::set_if_none_match(const std::string &field_name,
												const std::string &field_value) {
	if (has_multiple_field_names(field_name)) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	if (field_value == "*") {
		return set_multi_field_values(field_name, field_value, HttpMessageParser::is_token);
	} else {
		return set_multi_field_values(field_name, field_value, HttpMessageParser::is_entity_tag);
	}
}

/*
 Transfer-Encoding = [ transfer-coding *( OWS "," OWS transfer-coding ) ]
 */
Result<int, int> HttpRequest::set_transfer_encoding(const std::string &field_name,
													const std::string &field_value) {
	if (has_multiple_field_names(field_name)) {
		return Result<int, int>::err(STATUS_BAD_REQUEST);
	}

	return set_multi_field_values(field_name, field_value, is_transfer_coding);

	// std::stringstream	ss(field_value);
	// std::string			line;
	// std::string			line_without_ows;
	//
	// while(std::getline(ss, line, ','))
	// {
	// 	line_without_ows = HttpMessageParser::obtain_withoutows_value(line);
	// 	if (line_without_ows != "gzip" && line_without_ows != "compress" && line_without_ows \
	// 	!= "deflate" && line_without_ows != "gzip" && line_without_ows != "chunked")
	// 		// return;
	// 		return Result<int, int>::ok(STATUS_OK);
	// }
	// this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	// return Result<int, int>::ok(STATUS_OK);
}

// todo: Upgrade
/*
 Upgrade          = #protocol
 protocol         = protocol-name ["/" protocol-version]
 protocol-name    = token
 protocol-version = token
 */
// todo: map
//  map[name], map[version]
Result<int, int> HttpRequest::set_upgrade(const std::string &field_name,
										  const std::string &field_value)
{
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}
