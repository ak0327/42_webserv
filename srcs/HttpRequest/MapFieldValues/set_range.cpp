#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

/*
 Range = ranges-specifier
 ranges-specifier = range-unit "=" range-set
 range-unit       = token
 range-set        = 1#range-spec
 range-spec       = int-range
                  / suffix-range
                  / other-range

 int-range     = first-pos "-" [ last-pos ]
 first-pos     = 1*DIGIT
 last-pos      = 1*DIGIT

 suffix-range  = "-" suffix-length
 suffix-length = 1*DIGIT

 other-range   = 1*( %x21-2B / %x2D-7E )
               ; 1*(VCHAR excluding comma)
 https://www.rfc-editor.org/rfc/rfc9110#field.range

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
Result<std::map<std::string, std::string>, int>
parse_range_specifier(const std::string &field_value) {
	std::map<std::string, std::string> range_specifier;
	Result<int, int> parse_result;
	std::string key, value;
	std::size_t pos, end, len;
	std::string range_unit, range_spec;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	end = field_value.find('=', pos);
	if (end == std::string::npos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	len = end - pos;
	range_unit = field_value.substr(pos, len);
	pos += len;

	if (field_value[pos] != '=') {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	++pos;

	if (field_value[pos] == '\0') {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	range_spec = field_value.substr(pos);
	range_specifier[range_unit] = range_spec;
	return Result<std::map<std::string, std::string>, int>::ok(range_specifier);
}

// todo string -> set? vector?
bool is_valid_range_spec(const std::string &range_spec) {
	(void)range_spec;
	return true;
}

Result<int, int>
validate_range_specifier(const std::map<std::string, std::string> &range_specifier) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string range_unit, range_spec;

	if (range_specifier.size() != 1) {
		return Result<int, int>::err(ERR);
	}

	itr = range_specifier.begin();
	range_unit = itr->first;
	range_spec = itr->second;

	if (!HttpMessageParser::is_token(range_unit)) {
		return Result<int, int>::err(ERR);
	}

	if (!is_valid_range_spec(range_spec)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<std::map<std::string, std::string>, int>
parse_and_validate_range_specifier(const std::string &field_value) {
	std::map<std::string, std::string> range_specifier;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result, reformat_result;

	parse_result = parse_range_specifier(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	range_specifier = parse_result.get_ok_value();

	validate_result = validate_range_specifier(range_specifier);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	return Result<std::map<std::string, std::string>, int>::ok(range_specifier);
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
	result = parse_and_validate_range_specifier(field_value);
	if (result.is_ok()) {
		range_specifier = result.get_ok_value();
		this->_request_header_fields[field_name] = new MapFieldValues(range_specifier);
	}
	return Result<int, int>::ok(STATUS_OK);
}
