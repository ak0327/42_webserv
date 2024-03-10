#pragma once

# include <sys/types.h>
# include <map>
# include <utility>
# include <set>
# include <string>
# include <vector>
# include "webserv.hpp"
# include "CgiHandler.hpp"
# include "ConfigStruct.hpp"
# include "Dynamic.hpp"
# include "HttpRequest.hpp"
# include "Result.hpp"
# include "Session.hpp"


struct FileInfo {
	std::string name;
	off_t       size;
	std::string last_modified_time;  // dd-mm-yy hh:mm
};

struct FormData {
    std::string file_name;
    std::string content_type;
    std::vector<unsigned char> binary;
};

typedef std::string ScriptPath;
typedef std::string PathInfo;
typedef std::map<std::string, std::vector<std::string> > UrlEncodedFormData;
typedef std::map<std::string, Session>::iterator SessionItr;

class HttpResponse {
 public:
	explicit HttpResponse(const HttpRequest &request,
                          const ServerConfig &server_config,
                          const AddressPortPair &server_listen,
                          const AddressPortPair &client_listen,
                          std::map<std::string, Session> *sessions,
                          time_t keepalive_timeout);
	~HttpResponse();

    const std::vector<unsigned char> &body_buf() const;
	const std::vector<unsigned char> &get_response_message() const;

    ProcResult exec_method();
    ProcResult exec_cgi_process();
    ProcResult send_request_body_to_cgi();
    ProcResult recv_to_cgi_buf();
    void interpret_cgi_output();
    CgiParams get_cgi_params(const std::string &script_path,
                             const std::string &path_info);
    std::pair<ScriptPath, PathInfo> get_script_path_and_path_info();
    void create_response_message();

    Result<ProcResult, ErrMsg> recv_to_buf(int fd);
    Result<ProcResult, ErrMsg> send_http_response(int client_fd);

    void clear_cgi();
    int cgi_read_fd() const;
    int cgi_write_fd() const;
    time_t cgi_timeout_limit() const;
    void kill_cgi_process();
    bool is_exec_cgi();

    void create_echo_msg(const std::vector<unsigned char> &recv_msg);
    bool is_status_error() const;
    bool is_keepalive() const;

    void set_status_to_cgi_timeout();

#ifdef UNIT_TEST
    friend class HttpResponseFriend;
#endif

 private:
    const HttpRequest &request_;
    const ServerConfig &server_config_;
    const AddressPortPair server_listen_;
    const AddressPortPair client_listen_;
    std::map<std::string, Session> *sessions_;

    CgiHandler cgi_handler_;
    Dynamic dynamic_;

    StatusCode status_code_;

	/* response message */
	std::string status_line_;
	std::map<std::string, std::string> headers_;
    std::map<std::string, std::string> cookies_;
	std::vector<unsigned char> body_buf_;
    std::vector<unsigned char> response_msg_;

    time_t keepalive_timeout_sec_;

    void set_status_code(const StatusCode &set_status);

    StatusCode status_code() const;
    std::string get_rooted_path() const;
    std::string create_status_line(const StatusCode &code) const;
    std::string create_field_lines() const;

    bool is_executing_cgi() const;
    bool is_response_error_page() const;

    StatusCode is_resource_available(const Method &method) const;

    void process_method_not_allowed();

    bool has_valid_index_page() const;
    bool is_method_available() const;
    bool is_autoindex() const;
    bool is_redirect_target() const;
    bool is_support_content_type() const;
    static bool is_support_content_type(const std::string &path);
    static bool is_supported_by_media_type(const std::string &type);

    StatusCode redirect_to(const std::string &move_to);
    StatusCode upload_file();
    static std::string get_http_date();
    static std::string get_http_date(time_t time);
    static std::string get_http_date_jst(time_t time);

    void add_allow_header();
    void add_date_header();
    void add_server_header();
    void add_keepalive_header();
    void add_standard_headers();
    void add_cookie_headers();
    void add_content_header(const std::string &extension);
    void add_content_header_by_media_type(const std::string &media_type);
    void add_content_length();

    // GET
    StatusCode get_request_body();
    void get_error_page_to_body();
    bool is_cgi_file() const;
    bool is_redirect() const;

    StatusCode get_file_content(const std::string &file_path,
                                std::vector<unsigned char> *buf);
    StatusCode get_directory_listing(const std::string &directory_path_with_trailing_slash,
                                     std::vector<unsigned char> *buf);
    StatusCode get_redirect_content(const ReturnDirective &redirect);


    // POST
	StatusCode post_target();
    StatusCode upload_multipart_form_data(const std::string &boundary);

    Result<FormData, ProcResult> parse_multipart_form_data(const std::string &boundary);
    ProcResult parse_until_binary(const std::string &separator,
                                  std::string *file_name,
                                  std::string *content_type);
    ProcResult parse_binary_data(const std::string &separator,
                                 std::vector<unsigned char> *data);
    bool is_multipart_form_data(std::string *boundary);


    // DELETE
	StatusCode delete_target();


    // API
    bool is_dynamic_endpoint();
    bool is_urlencoded_form_data();
    StatusCode response_dynamic();
    StatusCode get_now();
    StatusCode show_form_data();
    StatusCode show_request_body();
    StatusCode get_cookie_login_page();
    StatusCode get_cookie_user_page();
    StatusCode get_session_login_page();
    StatusCode get_session_user_page();
    StatusCode get_urlencoded_form_content();
    UrlEncodedFormData parse_urlencoded_form_data(const std::vector<unsigned char> &request_body);

    bool is_logged_in_user();
    Result<SessionItr, bool> is_session_active_user();
    std::string get_user_name_from_cookie();
    std::string get_expire_from_cookie();
    Result<std::string, ProcResult> generate_new_id();
    ProcResult add_init_session_data(const std::map<std::string, std::string> &data);

    ProcResult update_session_data(SessionItr *itr);
    void update_counter(const SessionItr &itr);

    // unused
    HttpResponse(const HttpResponse &other);
	HttpResponse &operator=(const HttpResponse &rhs);
};
