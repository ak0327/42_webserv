#include <algorithm>
#include <vector>
#include "Constant.hpp"
#include "RequestLine.hpp"
#include "Result.hpp"
#include "Color.hpp"
#include "HttpMessageParser.hpp"
#include "StringHandler.hpp"

/* constructor, destructor */
RequestLine::RequestLine() {}

RequestLine::~RequestLine() {}


/* getter */
std::string	RequestLine::get_method(void) const {
	return this->_method;
}

std::string RequestLine::get_request_target(void) const {
	return this->_request_target;
}

std::string	RequestLine::get_http_version(void) const {
	return this->_http_version;
}


/* parse and validate */
Result<int, int> RequestLine::parse_and_validate(const std::string &line) {
	Result<int, int> parse_result, validate_result;

	parse_result = this->parse(line);
	if (parse_result.is_err()) {
		return Result<int, int>::err(NG);
	}

	validate_result = this->validate();
	if (validate_result.is_err()) {
		return Result<int, int>::err(NG);
	}

	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////
/* parse */

/*
 method = token
  line = "GET / HTTP/1.1"
      head^  ^delim_pos

 request-target = origin-form / absolute-form / authority-form / asterisk-form
  origin-form    = absolute-path [ "?" query ] ; http://www.example.org/where?q=now
  absolute-form  = absolute-URI ; http://www.example.org/pub/WWW/TheProject.html
  authority-form = authority ; www.example.com:80
  asterisk-form  = "*"

 HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
  HTTP-name     = %x48.54.54.50 ; "HTTP", case-sensitive
 */


// request-line   = method SP request-target SP HTTP-version CRLF
// line_wo_end_lf = method SP request-target SP HTTP-version CR
Result<int, int> RequestLine::parse(const std::string &line_wo_end_lf) {
	size_t pos, end_pos;
	Result<std::string, int> method_result;
	Result<std::string, int> request_target_result;
	Result<std::string, int> http_version_result;

	// method
	pos = 0;
	method_result = StringHandler::parse_pos_to_delimiter(line_wo_end_lf,
														  pos,
														  SP,
														  &end_pos);
	if (method_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	this->_method = method_result.get_ok_value();
	pos = end_pos;

	// SP
	if (line_wo_end_lf[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// request-target
	request_target_result = StringHandler::parse_pos_to_delimiter(line_wo_end_lf,
																  pos,
																  SP,
																  &end_pos);
	if (request_target_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	this->_request_target = request_target_result.get_ok_value();
	pos = end_pos;

	// SP
	if (line_wo_end_lf[pos] != SP) {
		return Result<int, int>::err(NG);
	}
	pos++;

	// HTTP-version
	http_version_result = StringHandler::parse_pos_to_delimiter(line_wo_end_lf,
																pos,
																CR,
																&end_pos);
	if (http_version_result.is_err()) {
		return Result<int, int>::err(NG);
	}
	this->_http_version = http_version_result.get_ok_value();
	pos = end_pos;

	// CR
	if (!(line_wo_end_lf[pos] == CR && line_wo_end_lf[pos + 1] == '\0')) {
		return Result<int, int>::err(NG);
	}
	return Result<int, int>::ok(OK);
}

////////////////////////////////////////////////////////////////////////////////
/* validate */
bool RequestLine::is_valid_request_target(const std::string &request_target) {
	return HttpMessageParser::is_printable(request_target);
}

Result<int, int> RequestLine::validate() const {
	if (!HttpMessageParser::is_valid_method(this->_method)) {
		return Result<int, int>::err(NG);
	}
	if (!is_valid_request_target(this->_request_target)) {
		return Result<int, int>::err(NG);
	}
	if (!HttpMessageParser::is_valid_http_version(this->_http_version)) {
		return Result<int, int>::err(NG);
	}
	return Result<int, int>::ok(OK);
}
