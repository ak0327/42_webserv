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

struct FormData {
    std::string file_name;
    std::vector<unsigned char> binary;
};

typedef std::vector<std::string> StringVector;
typedef std::map<std::string, StringVector> UrlEncodedFormData;

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
    bool is_status_error() const;

    // GET
    StatusCode get_request_body();
    std::string get_indexed_path();
    void get_error_page_to_body();
    bool is_cgi_file() const;
    bool is_redirect() const;
    StatusCode get_file_content(const std::string &file_path,
                                std::vector<unsigned char> *buf);
    StatusCode get_directory_listing(const std::string &directory_path,
                                     std::vector<unsigned char> *buf);
    StatusCode get_redirect_content(std::map<std::string, std::string> *headers);

    // POST
	StatusCode post_target();
    StatusCode get_urlencoded_form_content();
    StatusCode show_body();
    bool is_urlencoded_form_data();
    bool is_multipart_form_data();

    // DELETE
	StatusCode delete_target();

	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);
};
