#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

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

	result = HttpMessageParser::parse_map_field_values(field_value,
													   HttpMessageParser::skip_token,
													   HttpMessageParser::skip_token_or_quoted_string,
													   HttpMessageParser::skip_ows_comma_ows,
													   EQUAL_SIGN,
													   true);
	if (result.is_ok()) {
		cache_directive = result.ok_value();
		this->request_header_fields_[field_name] = new MapFieldValues(cache_directive);
	}
	return Result<int, int>::ok(STATUS_OK);
}
