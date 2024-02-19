#pragma once

# include <sys/types.h>
# include <map>
# include <set>
# include <string>
# include <vector>
# include "webserv.hpp"
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

	const std::vector<unsigned char> &get_response_message() const;

    Result<int, int> exec_method();
    Result<int, int> recv_cgi_result();
    Result<int, int> create_cgi_body();
    Result<int, int> create_response_message();

    int get_cgi_fd() const;
    bool is_cgi_processing(int *status);

    // todo: util
    static Result<std::vector<std::string>, int> get_interpreter(const std::string &file_path);

#ifdef ECHO
    HttpResponse();
    void create_echo_msg(const std::vector<unsigned char> &recv_msg);
    std::string get_echo_msg() const;
#endif

 private:
    const HttpRequest &request_;
    const ServerConfig &server_config_;

	StatusCode status_code_;

    int cgi_read_fd_;
    pid_t cgi_pid_;

	/* response message */
	std::string status_line_;
	std::map<std::string, std::string> headers_;

	// message-body = *OCTET
	std::vector<unsigned char> body_buf_;

    // send to client
    std::vector<unsigned char> response_message_;


	HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);


    std::string get_resource_path(const std::string &request_target);
    std::string create_field_lines() const;
    std::string create_status_line() const;

    // GET
    Result<Fd, int> get_request_body(const std::string &target_path);
    Result<int, int> get_path_content(const std::string &path, bool autoindex);
    void get_error_page();
    static bool is_directory(const std::string &path);
    static bool is_cgi_file(const std::string &path);
    Result<int, int> get_file_content(const std::string &file_path,
                                      const std::map<std::string, std::string> &mime_types,
                                      std::vector<unsigned char> *buf,
                                      int *status_code);
    Result<int, int> get_directory_listing(const std::string &directory_path,
                                           std::vector<unsigned char> *buf,
                                           int *status_code);
    Result<Fd, int> exec_cgi(const std::string &file_path,
                             int *cgi_read_fd,
                             pid_t *cgi_pid,
                             int *status_code);
    void close_cgi_fd();
    void kill_cgi_process();
    int execute_cgi_script_in_child(int socket_fds[2],
                                    const std::string &file_path,
                                    const std::string &query);
    Result<int, std::string> create_socketpair(int socket_fds[2]);
    std::vector<char *> get_argv_for_execve(const std::vector<std::string> &interpreter,
                                            const std::string &file_path);
    bool is_exec_timeout(time_t start_time, int timeout_sec);

    // POST
	Result<int, int> post_request_body(const std::string &target) {
        (void)target;
        this->status_code_ = STATUS_OK;
        return Result<int, int>::ok(OK);
    }

    // DELETE
	Result<int, int> delete_request_body(const std::string &target) {
        (void)target;
        this->status_code_ = STATUS_OK;
        return Result<int, int>::ok(OK);
    }
};
