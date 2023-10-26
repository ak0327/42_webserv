#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

void skip_range_unit(const std::string &str,
					 std::size_t start_pos,
					 std::size_t *end_pos) {
	HttpMessageParser::skip_token(str, start_pos, end_pos);
}

/*
 range-set        = 1#range-spec
 range-spec       = int-range
                  / suffix-range
                  / other-range
 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
void skip_range_set(const std::string &str,
					std::size_t start_pos,
					std::size_t *end_pos) {
	std::size_t pos, end;
	Result<std::size_t, int> skip_result;

	if (!end_pos) {
		return;
	}
	*end_pos = start_pos;
	if (str.empty() || str.length() <= start_pos) {
		return;
	}
	pos = start_pos;
	end = pos;

	while (str[pos]) {
		if (std::isdigit(str[pos])) {
			HttpMessageParser::skip_int_range(str, pos, &end);
		} else if (str[pos] == '-') {
			HttpMessageParser::skip_suffix_range(str, pos, &end);
		} else {
			HttpMessageParser::skip_other_range(str, pos, &end);
		}
		if (pos == end) {
			break;
		}
		pos = end;

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(str, COMMA, pos);
		if (skip_result.is_err()) {
			break;
		}
		pos = skip_result.get_ok_value();
	}
	*end_pos = pos;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

/*
 Range = ranges-specifier
 ranges-specifier = range-unit "=" range-set
 range-unit       = token
 range-set        = 1#range-spec
 range-spec       = int-range
                  / suffix-range
                  / other-range
 https://www.rfc-editor.org/rfc/rfc9110#field.range

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
Result<int, int> HttpRequest::set_range(const std::string &field_name,
										const std::string &field_value) {
	std::map<std::string, std::string> range_specifier;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);
	result = HttpMessageParser::parse_map_field_values(field_value,
													   skip_range_unit,
													   skip_range_set,
													   HttpMessageParser::skip_non);
	if (result.is_ok()) {
		range_specifier = result.get_ok_value();
		this->_request_header_fields[field_name] = new MapFieldValues(range_specifier);
	}
	return Result<int, int>::ok(STATUS_OK);
}
