#pragma once

# include <sys/types.h>
# include <map>
# include <set>
# include <string>
# include <vector>
# include "Result.hpp"

//------------------------------------------------------------------------------
/* tmp */
# define CRLF	"\r\n"
# define SP		" "
# define LF		"\n"

# define CR		"\r"

# define STATUS_OK				200
# define STATUS_BAD_REQUEST		400
# define STATUS_NOT_FOUND		404
# define STATUS_NOT_ACCEPTABLE	406
# define STATUS_SERVER_ERROR	500

extern const char error_301_page[];
extern const char error_302_page[];
extern const char error_303_page[];
extern const char error_307_page[];
extern const char error_308_page[];
extern const char error_400_page[];
extern const char error_401_page[];
extern const char error_402_page[];
extern const char error_403_page[];
extern const char error_404_page[];
extern const char error_405_page[];
extern const char error_406_page[];
extern const char error_408_page[];
extern const char error_409_page[];
extern const char error_410_page[];
extern const char error_411_page[];
extern const char error_412_page[];
extern const char error_413_page[];
extern const char error_414_page[];
extern const char error_415_page[];
extern const char error_416_page[];
extern const char error_421_page[];
extern const char error_429_page[];
extern const char error_494_page[];
extern const char error_495_page[];
extern const char error_496_page[];
extern const char error_497_page[];
extern const char error_500_page[];
extern const char error_501_page[];
extern const char error_502_page[];
extern const char error_503_page[];
extern const char error_504_page[];
extern const char error_505_page[];
extern const char error_507_page[];

enum e_method {
	GET,
	POST,
	DELETE,
	ERROR
};

struct file_info {
	std::string	name;
	off_t		size;
	std::string	last_modified_time;  // dd-mm-yy hh:mm
};

bool operator<(const file_info &lhs, const file_info &rhs);
std::string get_extension(const std::string &path);
bool is_directory(const std::string &path);
Result<std::vector<std::string>, int> get_interpreter(const std::string &file_path);

// todo: mv config?
bool is_cgi_file(const std::string &path);

class Config {
 public:
	Config() : autoindex_(false) {}
	explicit Config(bool autoindex) : autoindex_(autoindex) {}
	~Config() {}

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

	bool get_autoindex() const { return autoindex_; }
	void set_autoindex(bool autoindex) { autoindex_ = autoindex; }

 private:
	bool autoindex_;
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

//------------------------------------------------------------------------------

class HttpResponse {
 public:
	HttpResponse(const HttpRequest &request, const Config &config);
	~HttpResponse();

	std::string get_response_message() const;

 private:
	std::map<int, std::string> _status_reason_phrase;
	std::map<int, std::string> _error_pages;

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
						 const std::string &path,
						 bool autoindex);
	int post_request_body() { return 200; }
	int delete_request_body() { return 200; }

	std::string get_field_lines() const;

	Result<std::string, int> get_path_content(const std::string &path,
											  bool autoindex,
											  std::size_t *ret_content_length,
											  const std::map<std::string, std::string> &mime_types) const;

	Result<std::string, int> get_file_content(const std::string &file_path,
											  const std::map<std::string, std::string> &mime_types) const;

	Result<std::string, int> get_directory_listing(const std::string &directory_path) const;

	Result<std::string, int> get_cgi_result(const std::string &file_path,
											const std::string &query) const;
};
