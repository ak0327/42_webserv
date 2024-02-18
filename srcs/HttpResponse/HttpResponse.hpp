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
    Result<int, int> create_response_body();

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

	int get_request_body(const std::string &target) { (void)target; return STATUS_OK; }
	int post_request_body(const std::string &target) { (void)target; return STATUS_OK; }
	int delete_request_body(const std::string &target) { (void)target; return STATUS_OK; }

    static std::string get_resource_path(const std::string &request_target);

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
