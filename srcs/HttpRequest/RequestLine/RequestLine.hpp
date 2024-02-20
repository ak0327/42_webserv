#pragma once

# include <string>
# include "webserv.hpp"
# include "Result.hpp"

class RequestLine {
 public:
	RequestLine();
	RequestLine(const RequestLine &other);
	RequestLine& operator=(const RequestLine &rhs);
	~RequestLine();

	std::string	get_method() const;
	std::string get_request_target() const;
	std::string	get_http_version() const;

	Result<ProcResult, StatusCode> parse_and_validate(const std::string &line);

 private:
	Result<ProcResult, StatusCode> parse(const std::string &line);
	Result<ProcResult, StatusCode> validate() const;

	std::string method_;
	std::string request_target_;
	std::string http_version_;
};
