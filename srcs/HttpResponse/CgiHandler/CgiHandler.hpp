#pragma once

# include <ctime>
# include <string>
# include <vector>
# include "webserv.hpp"
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "MediaType.hpp"

struct CgiParams {
    std::vector<unsigned char> content;
    std::size_t content_length;
    std::string content_type;
    std::string query_string;
    std::string path_info;
    std::string script_path;

    CgiParams()
        : content(),
          content_length(0),
          content_type(),
          query_string(),
          path_info(),
          script_path() {}
};


class CgiHandler {
 public:
    CgiHandler();
    ~CgiHandler();

    void clear_cgi_process();
    void kill_cgi_process();
    void close_read_fd();
    void close_write_fd();

    int read_fd() const;
    int write_fd() const;
    pid_t pid() const;
    StatusCode cgi_status_code() const;
    time_t timeout_limit() const;
    void set_timeout_duration_sec(time_t timeout_sec);
    const std::vector<unsigned char> &cgi_body() const;
    void clear_recv_buf();

    bool is_processing(int *status);
    bool is_processing() const;
    bool is_process_timeout() const;

    void set_cgi_params(const CgiParams &params);
    ProcResult create_socket_pair(int to_child[2], int from_child[2]);
    ProcResult exec_script(const std::string &file_path);
    ProcResult send_request_body_to_cgi();
    ProcResult recv_cgi_output();
    StatusCode parse_document_response();

#ifdef UNIT_TEST
    friend class CgiHandlerFriend;
#endif

 private:
    int cgi_read_fd_;
    int cgi_write_fd_;
    pid_t cgi_pid_;

    time_t timeout_duration_sec_;
    time_t timeout_limit_;

    CgiParams params_;

    MediaType media_type_;
    StatusCode cgi_status_;

    std::size_t send_size_;
    std::vector<unsigned char> recv_buf_;


    void set_cgi_read_fd(int read_fd);
    void set_cgi_write_fd(int write_fd);
    void set_cgi_pid(pid_t pid);
    void set_timeout_limit();
    time_t timeout_duration_sec() const;

    Result<int, std::string> create_socketpair(int socket_fds[2]);
    int exec_script_in_child(int from_parant[2], int to_parent[2], const std::string &file_path);
    ProcResult handle_parent_fd(int to_child[2], int from_child[2]);
    ProcResult handle_child_fd(int from_parant[2], int to_parent[2]);

    std::string make_key_value_pair(const std::string &key,
                                    const std::string &value);
    char **create_envp(const CgiParams &params);
    char **create_argv(const std::string &file_path);
    void delete_char_double_ptr(char **ptr);

    void find_nl(const std::vector<unsigned char> &data,
                 std::vector<unsigned char>::const_iterator start,
                 std::vector<unsigned char>::const_iterator *nl);
    Result<std::string, ProcResult> get_line(const std::vector<unsigned char> &data,
                                             std::vector<unsigned char>::const_iterator start,
                                             std::vector<unsigned char>::const_iterator *ret);
    Result<std::string, ProcResult> pop_line_from_buf();

    static Result<std::vector<std::string>, ProcResult> get_interpreter(const std::string &file_path);

    void strcpy(char *dst, const char *src);


    CgiHandler(const CgiHandler &other);
    CgiHandler &operator=(const CgiHandler &other);
};
