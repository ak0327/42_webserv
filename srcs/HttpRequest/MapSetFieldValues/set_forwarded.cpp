#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"
#include "MapSetFieldValues.hpp"
#include "StringHandler.hpp"

namespace {

/*
 forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
 forwarded-pair    = token "=" value
 value             = token / quoted-string
 */
Result<std::map<std::string, std::string>, int>
parse_and_validate_forwarded_element(const std::string &field_value,
									 std::size_t start_pos,
									 std::size_t *end_pos) {
	std::map<std::string, std::string> forwarded_element;
	Result<int, int> parse_result, validate_result;
	std::string token, value;
	std::size_t pos, end;

	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = start_pos;
	while (true) {
		parse_result = HttpMessageParser::parse_parameter(field_value,
														  pos, &end,
														  &token, &value,
														  HttpMessageParser::skip_token,
														  HttpMessageParser::skip_token_or_quoted_string);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end;
		forwarded_element[token] = value;

		if (field_value[pos] == ';') {
			++pos;
			continue;
		}
		break;
	}
	*end_pos = pos;
	return Result<std::map<std::string, std::string>, int>::ok(forwarded_element);
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

/*
 Forwarded         = 1#forwarded-element
 forwarded-element = [ forwarded-pair ] *( ";" [ forwarded-pair ] )
 forwarded-pair    = token "=" value
 https://www.rfc-editor.org/rfc/rfc7239#section-4
 */
/*
 std::set<std::map<std::string, std::string> > forwarded_set = {forwarded1, forwarded2, ... };
  forwarded_i[token] = value
 */
Result<int, int> HttpRequest::set_forwarded(const std::string &field_name,
											const std::string &field_value) {
	std::set<std::map<std::string, std::string> > forwarded_set;
	Result<std::set<std::map<std::string, std::string> >, int> result;

	clear_field_values_of(field_name);

	result = HttpMessageParser::parse_map_set_field_values(field_value,
														   parse_and_validate_forwarded_element);
	if (result.is_ok()) {
		forwarded_set = result.get_ok_value();
		this->_request_header_fields[field_name] = new MapSetFieldValues(forwarded_set);
	}
	return Result<int, int>::ok(STATUS_OK);
}
