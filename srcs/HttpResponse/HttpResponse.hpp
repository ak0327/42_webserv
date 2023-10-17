#pragma once

# include <map>
# include <string>

# define CRLF	"\r\n"
# define SP		" "

// todo: tmp
enum method {
	GET,
	POST,
	DELETE
};

class Configuration {
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
	enum method get_method() const { return GET; }
	std::string get_target() const { return "/"; }
};

class HttpResponse {
 public:
	HttpResponse(const HttpRequest &request, const Configuration &config);
	~HttpResponse();

	std::string get_response_message() const;

 private:
	std::map<int, std::string> _status_codes;
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
	int get_request_body(const HttpRequest &request, const Configuration &config);
	int post_request_body() { return 200; }
	int delete_request_body() { return 200; }

	std::string get_response_headers() const;
};
