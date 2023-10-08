#pragma once

# include <string>
# include "Result.hpp"

class RequestLine {
 public:
	RequestLine();
	~RequestLine();

	std::string	get_method() const;
	std::string get_request_target() const;
	std::string	get_http_version() const;

	Result<int, int> parse_and_validate(const std::string &line);

 private:
	RequestLine& operator=(const RequestLine &other);
	RequestLine(const RequestLine &other);

	Result<int, int> parse(const std::string &line);
	Result<int, int> validate() const;

	static Result<std::string, int> parse_pos_to_delimiter(const std::string &line,
														   std::size_t *idx,
														   char tail_delimiter);

	static bool is_valid_method(const std::string &method);
	static bool is_valid_request_target(const std::string &request_target);
	static bool is_valid_http_version(const std::string &http_version);

	std::string _method;
	std::string _request_target;
	std::string _http_version;
};
