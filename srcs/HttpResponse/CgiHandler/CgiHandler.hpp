#pragma once

# include <ctime>
# include <string>
# include <vector>
# include "webserv.hpp"
# include "Constant.hpp"
# include "MediaType.hpp"

class CgiHandler {
 public:
    CgiHandler();
    ~CgiHandler();

    void clear_cgi_process();
    void kill_cgi_process();
    void close_cgi_fd();

    int fd() const;
    pid_t pid() const;
    StatusCode status_code() const;
    const std::vector<unsigned char> &cgi_body() const;

    bool is_processing(int *status);
    bool is_process_timeout();


    StatusCode exec_script(const std::string &file_path);
    StatusCode parse_document_response();

    ssize_t recv_to_buf(int fd);

#ifdef UTEST_FRIEND
    friend class CgiHandlerFriend;
#endif

 private:
    int cgi_read_fd_;
    pid_t cgi_pid_;

    time_t process_start_time_;
    time_t timeout_sec_;

    MediaType media_type_;
    StatusCode cgi_status_;
    std::vector<unsigned char> recv_buf_;


    void set_cgi_read_fd(int read_fd);
    void set_cgi_pid(pid_t pid);
    void set_start_time();
    time_t process_start_time();
    unsigned int timeout_sec();

    int exec_script_in_child(int socket_fds[2],
                             const std::string &file_path,
                             const std::string &query);
    Result<int, std::string> create_socketpair(int socket_fds[2]);
    std::vector<char *> get_argv_for_execve(const std::vector<std::string> &interpreter,
                                            const std::string &file_path);

    void find_nl(const std::vector<unsigned char> &data,
                 std::vector<unsigned char>::const_iterator start,
                 std::vector<unsigned char>::const_iterator *nl);
    Result<std::string, ProcResult> get_line(const std::vector<unsigned char> &data,
                                             std::vector<unsigned char>::const_iterator start,
                                             std::vector<unsigned char>::const_iterator *ret);
    Result<std::string, ProcResult> pop_line_from_buf();

    static Result<std::vector<std::string>, ProcResult> get_interpreter(const std::string &file_path);
};
