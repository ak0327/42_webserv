#include <iostream>
#include "Constant.hpp"
#include "Color.hpp"
#include "HttpMessageParser.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"

/* constructor, destructor */

MediaType::MediaType() {}

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

MediaType::MediaType(const std::string &type,
					 const std::string &subtype,
					 const std::map<std::string, std::string> &parameters)
	: _type(type),
	  _subtype(subtype),
	  _parameters(parameters) {
	Result<int, int> validate_result;

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

 */
Result<int, int> MediaType::parse(const std::string &field_value) {
	std::size_t end;
	Result<int, int> result;

	if (field_value.empty()) {
		return Result<int, int>::err(ERR);
	}
	result = HttpMessageParser::parse_madia_type(field_value, 0, &end,
												 &this->_type,
												 &this->_subtype,
												 &this->_parameters);
	if (result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	if (field_value[end] != '\0') {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}


Result<int, int> MediaType::validate() {
	if (!HttpMessageParser::is_valid_type(this->_type)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_subtype(this->_subtype)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_parameters(this->_parameters)) {
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
