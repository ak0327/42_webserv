#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

/*
 Upgrade          = #protocol
 protocol         = protocol-name ["/" protocol-version]
 protocol-name    = token
 protocol-version = token
 */
Result<int, int> HttpRequest::set_upgrade(const std::string &field_name,
										  const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);
	result = HttpMessageParser::parse_map_field_values(field_value,
													   HttpMessageParser::skip_token,
													   HttpMessageParser::skip_token,
													   HttpMessageParser::skip_ows_comma_ows,
													   SLASH,
													   true);
	if (result.is_ok()) {
		keep_alive_info = result.ok_value();
		this->request_header_fields_[field_name] = new MapFieldValues(keep_alive_info);
	}
	return Result<int, int>::ok(STATUS_OK);
}
