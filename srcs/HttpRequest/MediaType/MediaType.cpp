#include <iostream>
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "HttpMessageParser.hpp"
#include "MediaType.hpp"
#include "StringHandler.hpp"

/* constructor, destructor */

MediaType::MediaType() {}

MediaType::MediaType(const std::string &field_value) {
	Result<int, int> parse_result, validate_result;

	parse_result = this->parse(field_value);
	if (parse_result.is_err()) {
		this->result_ = Result<int, int>::err(ERR);
		return;
	}

	validate_result = this->validate();
	if (validate_result.is_err()) {
		this->result_ = Result<int, int>::err(ERR);
		return;
	}
	this->result_ = Result<int, int>::ok(OK);
}

MediaType::MediaType(const std::string &type,
					 const std::string &subtype,
					 const std::map<std::string, std::string> &parameters)
	: type_(type),
      subtype_(subtype),
      parameters_(parameters) {
	Result<int, int> validate_result;

	validate_result = this->validate();
	if (validate_result.is_err()) {
		this->result_ = Result<int, int>::err(ERR);
		return;
	}
	this->result_ = Result<int, int>::ok(OK);
}

MediaType::MediaType(const MediaType &other) {
	*this = other;
}

MediaType &MediaType::operator=(const MediaType &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->type_ = rhs.type_;
	this->subtype_ = rhs.subtype_;
	this->parameters_ = rhs.parameters_;
    this->result_ = rhs.result_;
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
												 &this->type_,
												 &this->subtype_,
												 &this->parameters_);
	if (result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	if (field_value[end] != '\0') {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}


Result<int, int> MediaType::validate() {
	if (!HttpMessageParser::is_valid_type(this->type_)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_subtype(this->subtype_)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_parameters(this->parameters_)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////
/* getter */

std::string MediaType::type() const { return this->type_; }
std::string MediaType::subtype() const { return this->subtype_; }
std::map<std::string, std::string> MediaType::parameters() const { return this->parameters_; }
bool MediaType::is_ok() const { return this->result_.is_ok(); }
bool MediaType::is_err() const { return this->result_.is_err(); }
