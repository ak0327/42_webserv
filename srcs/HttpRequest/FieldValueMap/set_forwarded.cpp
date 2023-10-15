#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueMap.hpp"

namespace {

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


}  // namespace

////////////////////////////////////////////////////////////////////////////////

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
