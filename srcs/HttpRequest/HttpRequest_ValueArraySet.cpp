#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

ValueArraySet* HttpRequest::ready_ValueArraySet(const std::string &all_value)
{
	std::vector<std::string>	value_array;
	std::stringstream			ss(all_value);
	std::string					line;

	while(std::getline(ss, line, ','))
		value_array.push_back(HttpMessageParser::obtain_withoutows_value(line));
	return (new ValueArraySet(value_array));
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
	std::vector<std::string>	value_array;
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


// todo: Content-Encoding
// Content-Encoding = [ content-coding *( OWS "," OWS content-coding )
// content-coding   = token
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
//
// todo: vector
Result<int, int> HttpRequest::set_content_encoding(const std::string &field_name,
												   const std::string &field_value)
{
	std::stringstream	ss(field_value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line != "gzip" && line != "compress" && line != "deflate" && line != "br")
			// return;
			return Result<int, int>::ok(STATUS_OK);
	}
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Content-Language
// Content-Language = [ language-tag *( OWS "," OWS language-tag ) ]
// https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
// todo: vector
Result<int, int> HttpRequest::set_content_language(const std::string &field_name,
												   const std::string &field_value)
{
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: If-Match
/*
 If-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]
 entity-tag = [ weak ] opaque-tag
 weak = %x57.2F ; W/
 opaque-tag = DQUOTE *etagc DQUOTE
 etagc = "!" / %x23-7E ; '#'-'~' / obs-text
 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
// todo: vector
Result<int, int> HttpRequest::set_if_match(const std::string &field_name,
										   const std::string &field_value)
{
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: If-None-Match
/*
 If-None-Match = "*" / [ entity-tag *( OWS "," OWS entity-tag ) ]

 https://www.rfc-editor.org/rfc/rfc9110#name-collected-abnf
 */
// todo: vector
Result<int, int> HttpRequest::set_if_none_match(const std::string &field_name,
												const std::string &field_value)
{
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
}

// todo: Transfer-Encoding
/*
 Transfer-Encoding = [ transfer-coding *( OWS "," OWS transfer-coding ) ]
 transfer-coding    = token *( OWS ";" OWS transfer-parameter )
 transfer-parameter = token BWS "=" BWS ( token / quoted-string )
 */
// todo: vector
Result<int, int> HttpRequest::set_transfer_encoding(const std::string &field_name,
													const std::string &field_value)
{
	std::stringstream	ss(field_value);
	std::string			line;
	std::string			line_without_ows;

	while(std::getline(ss, line, ','))
	{
		line_without_ows = HttpMessageParser::obtain_withoutows_value(line);
		if (line_without_ows != "gzip" && line_without_ows != "compress" && line_without_ows \
		!= "deflate" && line_without_ows != "gzip" && line_without_ows != "chunked")
			// return;
			return Result<int, int>::ok(STATUS_OK);
	}
	this->_request_header_fields[field_name] = this->ready_ValueArraySet(field_value);
	return Result<int, int>::ok(STATUS_OK);
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
