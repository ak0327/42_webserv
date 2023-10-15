#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "FieldValueMap.hpp"

namespace {

/* Keep-Alive */
Result<std::map<std::string, std::string>, int> parse_keep_alive_info(const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<int, int> parse_result;
	std::string key, value;
	std::size_t pos, end;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;
	while (true) {
		parse_result = FieldValueMap::parse_map_element(field_value, pos, &end, &key, &value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end;
		keep_alive_info[key] = value;

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

	return Result<std::map<std::string, std::string>, int>::ok(keep_alive_info);
}

Result<int, int> validate_keep_alive_info(const std::map<std::string, std::string> &keep_alive_info) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;
	bool succeed;

	if (keep_alive_info.empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = keep_alive_info.begin(); itr != keep_alive_info.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (key == std::string(TIMEOUT)) {
			HttpMessageParser::to_delta_seconds(value, &succeed);
			if (succeed) { continue; }
		} else if (HttpMessageParser::is_token(key)) {
			if (FieldValueMap::is_key_only(value)) { continue; }
			if (HttpMessageParser::is_token(value)) { continue; }
			if (HttpMessageParser::is_quoted_string(value)) { continue; }
		}
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

Result<int, int> reformat_delta_seconds(std::map<std::string, std::string> *keep_alive_info) {
	std::map<std::string, std::string>::iterator itr;
	std::string key, value;
	int delta_seconds;
	bool succeed;

	if (!keep_alive_info || keep_alive_info->empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = keep_alive_info->begin(); itr != keep_alive_info->end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (key != std::string(TIMEOUT)) { continue; }

		delta_seconds = HttpMessageParser::to_delta_seconds(value, &succeed);
		if (!succeed) {
			return Result<int, int>::err(ERR);
		}
		itr->second = StringHandler::to_string(delta_seconds);
	}

	return Result<int, int>::ok(OK);
}

/*
 keep-alive-info      =   "timeout" "=" delta-seconds
                        / keep-alive-extension
 keep-alive-extension = token [ "=" ( token / quoted-string ) ]
 https://datatracker.ietf.org/doc/html/draft-thomson-hybi-http-timeout-03#section-2

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension

 */
Result<std::map<std::string, std::string>, int> parse_and_validate_keep_alive_info(
		const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result, reformat_result;

	parse_result = parse_keep_alive_info(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	keep_alive_info = parse_result.get_ok_value();

	validate_result = validate_keep_alive_info(keep_alive_info);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	reformat_result = reformat_delta_seconds(&keep_alive_info);
	if (reformat_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	return Result<std::map<std::string, std::string>, int>::ok(keep_alive_info);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

/*
 Keep-Alive           = "Keep-Alive" ":" 1#keep-alive-info
 https://datatracker.ietf.org/doc/html/draft-thomson-hybi-http-timeout-03#section-2

 1#element => element *( OWS "," OWS element )
 https://triple-underscore.github.io/RFC7230-ja.html#abnf.extension
 */
Result<int, int> HttpRequest::set_keep_alive(const std::string &field_name,
											 const std::string &field_value) {
	std::map<std::string, std::string> keep_alive_info;
	Result<std::map<std::string, std::string>, int> result;

	clear_field_values_of(field_name);
	result = parse_and_validate_keep_alive_info(field_value);
	if (result.is_ok()) {
		keep_alive_info = result.get_ok_value();
		this->_request_header_fields[field_name] = new FieldValueMap(keep_alive_info);
	}
	return Result<int, int>::ok(STATUS_OK);
}
