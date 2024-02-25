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
	explicit HttpResponse(const HttpRequest &request,
                          const ServerConfig &server_config,
                          const AddressPortPair &pair);
	~HttpResponse();

    const std::vector<unsigned char> &body_buf() const;
	const std::vector<unsigned char> &get_response_message() const;

    ProcResult exec_method();
    ProcResult recv_to_cgi_buf();
    ProcResult interpret_cgi_output();
    void create_response_message();

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

#ifdef UNIT_TEST
    friend class HttpResponseFriend;
#endif

 private:
    const HttpRequest &request_;
    const ServerConfig &server_config_;
    const AddressPortPair address_port_pair_;
    CgiHandler cgi_handler_;

    StatusCode status_code_;

	/* response message */
	std::string status_line_;
	std::map<std::string, std::string> headers_;
	std::vector<unsigned char> body_buf_;
    std::vector<unsigned char> response_msg_;


    StatusCode status_code() const;
    void set_status_code(const StatusCode &set_status);

    std::string get_resource_path();
    std::string create_status_line(const StatusCode &code) const;
    std::string create_field_lines() const;
    bool is_executing_cgi() const;
    bool is_response_error_page() const;
    StatusCode check_resource_availability(const Method &method) const;
    void add_allow_header();
    void process_method_not_allowed();

    // GET
    StatusCode get_request_body(const std::string &resource_path);
    std::string get_indexed_path(const std::string &resource_path);
    void get_error_page_to_body();
    bool is_cgi_file() const;
    bool is_redirect() const;
    StatusCode get_file_content(const std::string &file_path,
                                std::vector<unsigned char> *buf);
    StatusCode get_directory_listing(const std::string &directory_path,
                                     std::vector<unsigned char> *buf);
    StatusCode get_redirect_content(std::map<std::string, std::string> *headers);

    // POST
	StatusCode post_target(const std::string &target);

    // DELETE
	StatusCode delete_target(const std::string &target);

	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);
};
