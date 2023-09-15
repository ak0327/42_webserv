#pragma once

# include <string>

# define CRLF	"\r\n"
# define SP		" "

// todo: tmp
enum method {
	GET,
	POST,
	DELETE
};

class HttpRequest {
 public:
	enum method get_method() const { return GET; }
};

class HttpResponse {
 public:
	explicit HttpResponse(const HttpRequest &request);
	HttpResponse(const HttpResponse &other);
	~HttpResponse();
	HttpResponse &operator=(const HttpResponse &rhs);

	std::string get_response_message() const;

	int get_request_body() { return 200; }  	// funcname: tmp
	int post_request_body() { return 200; } 	// funcname: tmp
	int delete_request_body() { return 200; }  	// funcname: tmp

 private:
	int _status_code;  // todo: std::string?
	// ...

	// response message
	std::string _status_line;		// status-line = HTTP-version SP status-code SP [ reason-phrase ]
	std::string _response_header;  	// field-line = field-name ":" OWS field-values OWS
	std::string _response_body;		// message-body = *OCTET
};
