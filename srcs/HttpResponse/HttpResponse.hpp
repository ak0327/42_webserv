#pragma once

# include <sys/types.h>
# include <map>
# include <set>
# include <string>
# include <vector>
# include "webserv.hpp"
# include "CgiHandler.hpp"
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
	explicit HttpResponse(const HttpRequest &request, const ServerConfig &server_config);
	~HttpResponse();

    const std::vector<unsigned char> &body_buf() const;
	const std::vector<unsigned char> &get_response_message() const;

    Result<ProcResult, StatusCode> exec_method(const StatusCode &status_code);
    Result<ProcResult, StatusCode> recv_to_cgi_buf();
    Result<ProcResult, StatusCode> interpret_cgi_output();
    Result<ProcResult, StatusCode> create_response_message(const StatusCode &code);

    ssize_t recv_to_buf(int fd);

    void clear_cgi();
    int cgi_fd() const;
    time_t cgi_timeout_limit() const;
    void kill_cgi_process();

#ifdef ECHO
    HttpResponse();
    void create_echo_msg(const std::vector<unsigned char> &recv_msg);
    std::string get_echo_msg() const;
#endif

#ifdef UTEST_FRIEND
    friend class HttpResponseFriend;
#endif

 private:
    const HttpRequest &request_;
    const ServerConfig &server_config_;
    CgiHandler cgi_handler_;

	/* response message */
	std::string status_line_;
	std::map<std::string, std::string> headers_;
	std::vector<unsigned char> body_buf_;
    std::vector<unsigned char> response_msg_;


    std::string get_resource_path();
    std::string create_status_line(const StatusCode &code) const;
    std::string create_field_lines() const;
    bool is_executing_cgi() const;
    bool is_response_error_page(const StatusCode &status_code) const;

    // GET
    StatusCode get_request_body(const std::string &resource_path);
    std::string get_indexed_path(const std::string &resource_path);
    void get_error_page(const StatusCode &code);
    static bool is_directory(const std::string &path);
    static bool is_cgi_file(const std::string &path);
    StatusCode get_file_content(const std::string &file_path, std::vector<unsigned char> *buf);
    StatusCode get_directory_listing(const std::string &directory_path,
                                     std::vector<unsigned char> *buf);

    // POST
	StatusCode post_request_body(const std::string &target) {
        (void)target;
        return StatusOk;
    }

    // DELETE
	StatusCode delete_request_body(const std::string &target) {
        (void)target;
        return StatusOk;
    }


	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);
};
