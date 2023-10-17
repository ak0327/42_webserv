#include <algorithm>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"
#include "MapFieldValues.hpp"

namespace {

Result<std::string, int> parse_protocol_name(const std::string &field_value,
											 std::size_t start_pos,
											 std::size_t *end_pos) {
	std::size_t pos, len;
	std::string protocol_name;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	pos = start_pos;

	len = 0;
	while (field_value[pos + len]
		&& field_value[pos + len] != '/'
		&& field_value[pos + len] != SP
		&& field_value[pos + len] != COMMA) {
		++len;
	}

	protocol_name = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<std::string, int>::ok(protocol_name);
}

Result<std::string, int> parse_protocol_version(const std::string &field_value,
											 	std::size_t start_pos,
											 	std::size_t *end_pos) {
	std::size_t pos, len;
	std::string protocol_version;

	if (!end_pos) {
		return Result<std::string, int>::err(ERR);
	}
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	len = 0;
	pos = start_pos;
	while (field_value[pos + len]
		   && field_value[pos + len] != SP
		   && field_value[pos + len] != COMMA) {
		++len;
	}
	protocol_version = field_value.substr(pos, len);
	pos += len;

	*end_pos = pos;
	return Result<std::string, int>::ok(protocol_version);
}

/*
 Upgrade          = #protocol
 protocol         = protocol-name ["/" protocol-version]
 protocol-name    = token
 protocol-version = token

 1#element => element *( OWS "," OWS element )
 */
Result<std::map<std::string, std::string>, int>
parse_protocol(const std::string &field_value) {
	std::map<std::string, std::string> range_specifier;
	Result<std::string, int> parse_name_result, parse_version_result;
	std::string key, value;
	std::size_t pos, end;
	std::string protocol_name, protocol_version;

	if (field_value.empty()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	pos = 0;

	while (true) {
		// protocol_name
		parse_name_result = parse_protocol_name(field_value, pos, &end);
		if (parse_name_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		protocol_name = parse_name_result.get_ok_value();
		pos = end;

		// "/"
		if (field_value[pos] == '/') {
			++pos;
		}

		// protocol_version
		parse_version_result = parse_protocol_version(field_value, pos, &end);
		if (parse_version_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		protocol_version = parse_version_result.get_ok_value();
		pos = end;

		// std::cout << CYAN << "name:[" <<  protocol_name<< "], version:[" << protocol_version << "]" << RESET << std::endl;
		range_specifier[protocol_name] = protocol_version;

		if (field_value[pos] == '\0') {
			break;
		}

		// OWS "," OWS
		HttpMessageParser::skip_ows(field_value, &pos);
		if (field_value[pos] != ',') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);
	}
	return Result<std::map<std::string, std::string>, int>::ok(range_specifier);
}

/*
 protocol         = protocol-name ["/" protocol-version]
 protocol-name    = token
 protocol-version = token
 */
Result<int, int>
validate_protocol(const std::map<std::string, std::string> &protocol) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string key, value;

	if (protocol.empty()) {
		return Result<int, int>::err(ERR);
	}

	for (itr = protocol.begin(); itr != protocol.end(); ++itr) {
		key = itr->first;
		value = itr->second;

		if (HttpMessageParser::is_token(key)
			&& (value.empty() || HttpMessageParser::is_token(value))) {
			continue;
		}
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

Result<std::map<std::string, std::string>, int>
parse_and_validate_protocol(const std::string &field_value) {
	std::map<std::string, std::string> protocol;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<int, int> validate_result, reformat_result;

	parse_result = parse_protocol(field_value);
	if (parse_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}
	protocol = parse_result.get_ok_value();

	validate_result = validate_protocol(protocol);
	if (validate_result.is_err()) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	return Result<std::map<std::string, std::string>, int>::ok(protocol);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

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
	result = parse_and_validate_protocol(field_value);
	if (result.is_ok()) {
		keep_alive_info = result.get_ok_value();
		this->_request_header_fields[field_name] = new MapFieldValues(keep_alive_info);
	}
	return Result<int, int>::ok(STATUS_OK);
}
