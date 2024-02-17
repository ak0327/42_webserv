#pragma once

# include <sys/types.h>
# include <map>
# include <set>
# include <string>
# include <vector>
# include "ConfigStruct.hpp"
# include "HttpRequest.hpp"
# include "Result.hpp"

//------------------------------------------------------------------------------
/* tmp */
# define CRLF	"\r\n"
# define SP		" "

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

struct file_info {
	std::string	name;
	off_t		size;
	std::string	last_modified_time;  // dd-mm-yy hh:mm
};

// std::map<std::string, std::string> get_mime_types() {
//     std::map<std::string, std::string> types;
//
//     types["html"] = "text/html";
//     types["css"] = "text/css";
//     types["text"] = "text/plain";
//
//     types["gif"] = "image/gif";
//     types["jpeg"] = "image/jpeg";
//     types["jpg"] = "image/jpg";
//     types["png"] = "image/png";
//     return types;
// }

// bool operator<(const file_info &lhs, const file_info &rhs);
// std::string get_extension(const std::string &path);
// bool is_directory(const std::string &path);

// todo: mv config?
// bool is_cgi_file(const std::string &path);

//------------------------------------------------------------------------------

class HttpResponse {
 public:
	explicit HttpResponse(const HttpRequest &request);
	~HttpResponse();

	std::string get_response_message() const;

    Result<int, int> exec_method();

#ifdef ECHO
    HttpResponse();
    void create_echo_msg(const std::vector<unsigned char> &recv_msg);
    std::string get_echo_msg() const;
#endif

 private:
    const HttpRequest &request_;
	StatusCode status_code_;

	/* response message */
	// status-line = HTTP-version SP status-code SP [ reason-phrase ]
	std::string status_line_;

	// field-line = field-name ":" OWS field-values OWS
	std::map<std::string, std::string> response_headers_;

	// message-body = *OCTET
	std::vector<unsigned char> response_body_;

    // send to client
    std::vector<unsigned char> response_message_;

    // echo test
    std::string echo_message_;  // for test;

	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);

	int get_request_body() { return 200; };
	int post_request_body() { return 200; }
	int delete_request_body() { return 200; }

	std::string get_field_lines() const;

	// Result<std::string, int> get_path_content(const std::string &path,
	// 										  bool autoindex,
	// 										  std::size_t *ret_content_length,
	// 										  const std::map<std::string, std::string> &mime_types) const;
    //
	// Result<std::string, int> get_file_content(const std::string &file_path,
	// 										  const std::map<std::string, std::string> &mime_types) const;
    //
	// Result<std::string, int> get_directory_listing(const std::string &directory_path) const;
    //
	// Result<std::string, int> get_cgi_result(const std::string &file_path) const;
};
