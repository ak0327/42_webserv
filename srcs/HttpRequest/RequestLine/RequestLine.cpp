#include <algorithm>
#include <iostream>
#include <vector>
#include "Constant.hpp"
#include "RequestLine.hpp"
#include "Result.hpp"
#include "Color.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

/* constructor, destructor */
RequestLine::RequestLine() {}

RequestLine::RequestLine(const RequestLine &other) {
	*this = other;
}

RequestLine::~RequestLine() {}

RequestLine &RequestLine::operator=(const RequestLine &rhs) {
	if (this == &rhs) {
		return *this;
	}
    method_ = rhs.method_;
    request_target_ = rhs.request_target_;
    http_version_ = rhs.http_version_;
	return *this;
}

/* getter */
std::string	RequestLine::get_method(void) const {
	return this->method_;
}

std::string RequestLine::get_request_target(void) const {
	return this->request_target_;
}

std::string	RequestLine::get_http_version(void) const {
	return this->http_version_;
}


/* parse and validate */
Result<int, int> RequestLine::parse_and_validate(const std::string &line) {
	Result<int, int> parse_result, validate_result;

	parse_result = this->parse(line);
	if (parse_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	validate_result = this->validate();
	if (validate_result.is_err()) {
		return Result<int, int>::err(ERR);
	}

	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////
/* parse */

/*
 method = token
  line = "GET / HTTP/1.1"
      head^  ^delim_pos
 */

// request-line   = method SP request-target SP HTTP-version CRLF
// line_wo_end_lf = method SP request-target SP HTTP-version CR
// line           = method SP request-target SP HTTP-version
Result<int, int> RequestLine::parse(const std::string &line) {
	size_t pos, end_pos;
	Result<std::string, int> method_result;
	Result<std::string, int> request_target_result;
	Result<std::string, int> http_version_result;

	// method
	pos = 0;
	method_result = StringHandler::parse_pos_to_delimiter(line,
														  pos,
														  &end_pos,
														  SP);
	if (method_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	this->method_ = method_result.get_ok_value();
	pos = end_pos;

	// SP
	if (line[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	// request-target
	request_target_result = StringHandler::parse_pos_to_delimiter(line,
																  pos,
																  &end_pos,
																  SP);
	if (request_target_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	this->request_target_ = request_target_result.get_ok_value();
	pos = end_pos;

	// SP
	if (line[pos] != SP) {
		return Result<int, int>::err(ERR);
	}
	pos++;

	// HTTP-version
	this->http_version_ = line.substr(pos);
	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////

/*
 request-line = method SP request-target SP HTTP-version
 https://triple-underscore.github.io/http1-ja.html#p.request-line
 */
Result<int, int> RequestLine::validate() const {
	if (!HttpMessageParser::is_valid_method(this->method_)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_request_target(this->request_target_)) {
		return Result<int, int>::err(ERR);
	}
	if (!HttpMessageParser::is_valid_http_version(this->http_version_)) {
		return Result<int, int>::err(ERR);
	}
	return Result<int, int>::ok(OK);
}
