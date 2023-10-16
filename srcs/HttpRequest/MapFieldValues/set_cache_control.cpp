#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

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
		parse_result = MapFieldValues::parse_map_element(field_value, pos, &end, &key, &value);
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

		if (!HttpMessageParser::is_token(key)) {
			return Result<int, int>::err(ERR);
		}

		if (MapFieldValues::is_key_only(value)) { continue; }
		if (HttpMessageParser::is_token(value)) {
			continue; }
		if (HttpMessageParser::is_quoted_string(value)) {
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
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	cache_directive = parse_result.get_ok_value();

	validate_result = validate_cache_directive(cache_directive);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	return Result<std::map<std::string, std::string>, int>::ok(cache_directive);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

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
		this->_request_header_fields[field_name] = new MapFieldValues(cache_directive);
	}
	return Result<int, int>::ok(STATUS_OK);
}
