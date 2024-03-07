#include <algorithm>
#include <iostream>
#include <vector>
#include "webserv.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
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
std::string	RequestLine::method() const {
	return this->method_;
}

std::string RequestLine::target() const {
	return this->request_target_;
}

std::string	RequestLine::http_version() const {
	return this->http_version_;
}

std::string	RequestLine::query() const {
    return this->query_;
}

/* parse and validate */
Result<ProcResult, StatusCode> RequestLine::parse_and_validate(const std::string &line) {
	Result<ProcResult, StatusCode> parse_result, validate_result;
    DEBUG_PRINT(YELLOW, "[request line] parse");

	parse_result = this->parse(line);
	if (parse_result.is_err()) {
        this->http_version_ = std::string(HTTP_1_1);  // needed for response
        DEBUG_PRINT(YELLOW, "[request line] parse error -> 400");
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}

    DEBUG_PRINT(YELLOW, "[request line] validate");
    validate_result = this->validate();
	if (validate_result.is_err()) {
        this->http_version_ = std::string(HTTP_1_1);  // needed for response
        StatusCode error_status = validate_result.err_value();
        DEBUG_PRINT(YELLOW, "[request line] validate error -> %d", error_status);
        return Result<ProcResult, StatusCode>::err(error_status);
	}

    DEBUG_PRINT(YELLOW, "[request line] ok");
    update_target_path();
    separate_target_and_query();
	return Result<ProcResult, StatusCode>::ok(Success);
}

////////////////////////////////////////////////////////////////////////////////
/* parse */

// bool is_request_target_directory(const std::string &target) {
//     std::string extension = StringHandler::get_extension(target);
//     return extension.empty();
// }


/*
 method = token
  line = "GET / HTTP/1.1"
      head^  ^delim_pos
 */

// request-line   = method SP request-target SP HTTP-version CRLF
// line_wo_end_lf = method SP request-target SP HTTP-version CR
// line           = method SP request-target SP HTTP-version
Result<ProcResult, StatusCode> RequestLine::parse(const std::string &line) {
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
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	this->method_ = method_result.ok_value();
	pos = end_pos;

	// SP
	if (line[pos] != SP) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	pos++;

	// request-target
	request_target_result = StringHandler::parse_pos_to_delimiter(line,
																  pos,
																  &end_pos,
																  SP);
	if (request_target_result.is_err()) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
    this->request_target_ = request_target_result.ok_value();
	pos = end_pos;

	// SP
	if (line[pos] != SP) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}
	pos++;

	// HTTP-version
	this->http_version_ = line.substr(pos);
	return Result<ProcResult, StatusCode>::ok(Success);
}

////////////////////////////////////////////////////////////////////////////////

/*
 request-line = method SP request-target SP HTTP-version
 https://triple-underscore.github.io/http1-ja.html#p.request-line
 */
Result<ProcResult, StatusCode> RequestLine::validate() const {
    Result<ProcResult, StatusCode> method_result = validate_request_method();
    if (method_result.is_err()) {
        return Result<ProcResult, StatusCode>::err(method_result.err_value());
    }

	if (!HttpMessageParser::is_valid_request_target(this->request_target_)) {
		return Result<ProcResult, StatusCode>::err(BadRequest);
	}

    Result<ProcResult, StatusCode> version_result = validate_request_http_version();
    if (version_result.is_err()) {
		return Result<ProcResult, StatusCode>::err(version_result.err_value());
	}
	return Result<ProcResult, StatusCode>::ok(Success);
}


Result<ProcResult, StatusCode> RequestLine::validate_request_method() const {
    if (!HttpMessageParser::is_valid_method(this->method())) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }

    // if (this->method() != std::string(GET_METHOD)
    //     && this->method() != std::string(POST_METHOD)
    //     && this->method() != std::string(DELETE_METHOD)) {
    //     return Result<ProcResult, StatusCode>::err(MethodNotAllowed);
    // }
    return Result<ProcResult, StatusCode>::ok(Success);
}


Result<ProcResult, StatusCode> RequestLine::validate_request_http_version() const {
    if (!HttpMessageParser::is_valid_http_version(this->http_version())) {
        return Result<ProcResult, StatusCode>::err(BadRequest);
    }

    if (this->http_version() != std::string(HTTP_1_1)) {
        return Result<ProcResult, StatusCode>::err(HTTPVersionNotSupported);
    }
    return Result<ProcResult, StatusCode>::ok(Success);
}


void RequestLine::update_target_path() {
    std::string decoded = StringHandler::decode(this->request_target_);
    std::string normalized = StringHandler::normalize_to_absolute_path(decoded);
    this->request_target_ = normalized;
}

void RequestLine::separate_target_and_query() {
    std::string target = this->request_target_;
    std::size_t pos = 0;
    while (pos < target.length() && target[pos] != '?') {
        ++pos;
    }
    if (pos == target.length()) {
        return;
    }
    this->request_target_ = target.substr(0, pos);
    this->query_ = target.substr(pos + 1);
}
