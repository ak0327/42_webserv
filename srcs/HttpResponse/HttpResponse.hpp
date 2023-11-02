#pragma once

# include <map>
# include <string>
# include "Result.hpp"

//------------------------------------------------------------------------------
/* tmp */
# define CRLF	"\r\n"
# define SP		" "

# define STATUS_OK				200
# define STATUS_BAD_REQUEST		400
# define STATUS_NOT_FOUND		404
# define STATUS_NOT_ACCEPTABLE	406


enum e_method {
	GET,
	POST,
	DELETE,
	ERROR
};

class Config {
 public:
	std::map<std::string, std::string> get_locations() const {
		std::map<std::string, std::string> tmp;
		return tmp;
	}
	std::map<std::string, std::string> get_mime_types() const {
		std::map<std::string, std::string> types;

		types["html"] = "text/html";
		types["css"] = "text/css";
		types["text"] = "text/plain";

		types["gif"] = "image/gif";
		types["jpeg"] = "image/jpeg";
		types["jpg"] = "image/jpg";
		types["png"] = "image/png";
		return types;
	}
};

class HttpRequest {
 public:
	HttpRequest()
		: method_("GET"), request_target_("/") {}
	HttpRequest(const std::string &method, const std::string &request_target)
		: method_(method), request_target_(request_target) {}
	HttpRequest(const HttpRequest &other) { *this = other; }
	~HttpRequest() {}

	HttpRequest &operator=(const HttpRequest &rhs) {
		if (this == &rhs) {
			return *this;
		}
		method_ = rhs.method_;
		request_target_ = rhs.request_target_;
		return *this;
	}

	std::string get_method() const { return method_; }
	std::string get_request_target() const { return request_target_; }

	void set_method(enum e_method method) {
		if (method == GET) { method_ = "GET"; }
		if (method == POST) { method_ = "POST"; }
		if (method == DELETE) { method_ = "DELETE"; }
	}
	void set_request_target(const std::string &request_target) { request_target_ = request_target; }

 private:
	std::string method_;
	std::string request_target_;
};

// todo: mv lib
Result<std::string, int> get_file_content(const std::string &file_path,
										  size_t *ret_content_length);

//------------------------------------------------------------------------------

class HttpResponse {
 public:
	HttpResponse(const HttpRequest &request, const Config &config);
	~HttpResponse();

	std::string get_response_message() const;

 private:
	std::map<int, std::string> _status_reason_phrase;
	int _status_code;  // todo: std::string?
	// ...
	std::map<std::string, std::string> _headers;

	/* response message */
	// status-line = HTTP-version SP status-code SP [ reason-phrase ]
	std::string _status_line;

	// field-line = field-name ":" OWS field-values OWS
	std::map<std::string, std::string> _response_headers;

	// message-body = *OCTET
	std::string _response_body;


	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);

	// todo: tmp
	int get_request_body(const HttpRequest &request,
						 const Config &config,
						 const std::string &path);
	int post_request_body() { return 200; }
	int delete_request_body() { return 200; }

	std::string get_field_lines() const;
};
