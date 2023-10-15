#include <iostream>
#include "Constant.hpp"
#include "Color.hpp"
#include "HttpMessageParser.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"

////////////////////////////////////////////////////////////////////////////////
/* sub func */

namespace {

// type = token
bool is_valid_type(const std::string &type) {
	return HttpMessageParser::is_token(type);
}

// subtype = token
bool is_valid_subtype(const std::string &subtype) {
	return HttpMessageParser::is_token(subtype);
}

/*
 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
bool is_valid_parameters(const std::map<std::string, std::string> &parameters) {
	std::map<std::string, std::string>::const_iterator itr;
	std::string parameter_name, parameter_value;

	for (itr = parameters.begin(); itr != parameters.end(); ++itr) {
		parameter_name = itr->first;
		parameter_value = itr->second;

		if (!HttpMessageParser::is_token(parameter_name)) {
			return false;
		}
		if (!HttpMessageParser::is_token(parameter_value)
			&& !HttpMessageParser::is_quoted_string(parameter_value)) {
			return false;
		}
	}
	return true;
}

/*
 media-type = type "/" subtype parameters
 subtype = token
 parameters = *( OWS ";" OWS [ parameter ] )
 */
Result<std::string, int> parse_subtype(const std::string &field_value,
									   std::size_t start_pos,
									   std::size_t *end_pos) {
	std::size_t len;
	std::string subtype;

	if (!end_pos) { return Result<std::string, int>::err(ERR); }

	len = 0;
	while (true) {
		if (field_value[start_pos + len] == '\0') { break; }
		if (field_value[start_pos + len] == SP) { break; }
		if (field_value[start_pos + len] == ';') { break; }
		++len;
	}
	if (len == 0) {
		return Result<std::string, int>::err(ERR);
	}
	subtype = field_value.substr(start_pos, len);
	*end_pos = start_pos + len;
	return Result<std::string, int>::ok(subtype);
}

/*
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
Result<int, int> parse_parameter(const std::string &field_value,
								 std::size_t start_pos,
								 std::size_t *end_pos,
								 std::string *parameter_name,
								 std::string *parameter_value) {
	std::size_t pos, end, len;
	Result<std::string, int> parse_name_result;

	if (!end_pos || !parameter_name || !parameter_value) {
		return Result<int, int>::err(ERR);
	}

	// parameter-name
	pos = start_pos;
	parse_name_result = StringHandler::parse_pos_to_delimiter(field_value,
															  pos, '=', &end);
	if (parse_name_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*parameter_name = parse_name_result.get_ok_value();
	pos = end;

	// =
	if (field_value[pos] != '=') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// parameter-value
	len = 0;
	if (HttpMessageParser::is_tchar(field_value[pos])) {
		while (field_value[pos + len] && HttpMessageParser::is_tchar(field_value[pos + len])) {
			++len;
		}
	} else if (field_value[pos] == '"') {
		HttpMessageParser::skip_quoted_string(field_value, pos, &end);
		if (pos == end) {
			return Result<int, int>::err(ERR);
		}
		len = end - pos;
	} else {
		return Result<int, int>::err(ERR);
	}

	if (len == 0) {
		return Result<int, int>::err(ERR);
	}
	*parameter_value = field_value.substr(pos, len);
	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}


/*
 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
Result<std::map<std::string, std::string>, int> parse_parameters(const std::string &field_value,
																 std::size_t start_pos,
																 std::size_t *end_pos) {
	std::size_t pos, end;
	std::map<std::string, std::string> parameters;
	std::string parameter_name, parameter_value;
	Result<int, int> parse_result;


	if (!end_pos) {
		return Result<std::map<std::string, std::string>, int>::err(ERR);
	}

	if (field_value[start_pos] == '\0') {
		return Result<std::map<std::string, std::string>, int>::ok(parameters);
	}

	pos = start_pos;
	while (field_value[pos]) {
		HttpMessageParser::skip_ows(field_value, &pos);
		if (field_value[pos] != ';') {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		++pos;
		HttpMessageParser::skip_ows(field_value, &pos);

		parse_result = parse_parameter(field_value, pos, &end,
									   &parameter_name,
									   &parameter_value);
		if (parse_result.is_err()) {
			return Result<std::map<std::string, std::string>, int>::err(ERR);
		}
		pos = end;
		parameters[parameter_name] = parameter_value;
	}

	*end_pos = pos;
	return Result<std::map<std::string, std::string>, int>::ok(parameters);
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////
/* constructor, destructor */

MediaType::MediaType(const std::string &field_value) {
	Result<int, int> parse_result, validate_result;


	parse_result = this->parse(field_value);
	if (parse_result.is_err()) {
		this->_result = Result<int, int>::err(ERR);
		return;
	}

	validate_result = this->validate();
	if (validate_result.is_err()) {
		this->_result = Result<int, int>::err(ERR);
		return;
	}
	this->_result = Result<int, int>::ok(OK);
}

MediaType::MediaType(const MediaType &other) {
	*this = other;
}

MediaType &MediaType::operator=(const MediaType &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_type = rhs._type;
	this->_subtype = rhs._subtype;
	this->_parameters = rhs._parameters;
	return *this;
}

MediaType::~MediaType() {}

////////////////////////////////////////////////////////////////////////////////
/* parse, validate */

/*
 Content-Type = media-type
 media-type = type "/" subtype parameters

 type = token
 subtype = token

 parameters = *( OWS ";" OWS [ parameter ] )
 parameter = parameter-name "=" parameter-value
 parameter-name = token
 parameter-value = ( token / quoted-string )
 */
Result<int, int> MediaType::parse(const std::string &field_value) {
	std::size_t pos, end_pos;
	Result<std::string, int> type_result, subtype_result;
	Result<std::map<std::string, std::string>, int> parameters_result;


	if (field_value.empty()) {
		return Result<int, int>::err(ERR);
	}

	pos = 0;
	type_result = StringHandler::parse_pos_to_delimiter(field_value, pos, '/', &end_pos);
	if (type_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	this->_type = type_result.get_ok_value();
	pos = end_pos;

	if (field_value[pos] != '/') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	subtype_result = parse_subtype(field_value, pos, &end_pos);
	if (subtype_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	this->_subtype = subtype_result.get_ok_value();
	pos = end_pos;

	parameters_result = parse_parameters(field_value, pos, &end_pos);
	if (parameters_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	this->_parameters = parameters_result.get_ok_value();
	pos = end_pos;

	if (field_value[pos] != '\0') {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

Result<int, int> MediaType::validate() {
	if (!is_valid_type(this->_type)) {
		return Result<int, int>::err(ERR);
	}
	if (!is_valid_subtype(this->_subtype)) {
		return Result<int, int>::err(ERR);
	}
	if (!is_valid_parameters(this->_parameters)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////
/* getter */

std::string MediaType::get_type() const { return this->_type; }
std::string MediaType::get_subtype() const { return this->_subtype; }
std::map<std::string, std::string> MediaType::get_parameters() const { return this->_parameters; }
bool MediaType::is_ok() const { return this->_result.is_ok(); }
bool MediaType::is_err() const { return this->_result.is_err(); }
