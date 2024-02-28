#pragma once

# include <string>
# include <vector>
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Config.hpp"
# include "HttpRequest.hpp"
# include "HttpResponse.hpp"
# include "Result.hpp"
# include "webserv.hpp"

enum SessionState {
    kSessionInit,

    kReceivingRequest,
    kParsingRequest,
    kReceivingBody,

    kReadingRequest,

    kExecutingMethod,
    kCreatingResponseBody,
    kCreatingCGIBody,

    kReadingFile,  // unused
    kExecuteCGI,
    kSendingRequestBodyToCgi,
    kReceivingCgiResponse,

    kSendingResponse,

    kSessionCompleted,
    kSessionError
};


typedef Result<ProcResult, std::string> SessionResult;

class ClientSession {
 public:
    ClientSession(int socket_fd,
                  int client_fd,
                  const AddressPortPair &client_listen,
                  const Config &config);

    ~ClientSession();

    int client_fd() const;
    int cgi_read_fd() const;
    int cgi_write_fd() const;
    SessionState session_state() const;

    void set_session_state(const SessionState &set_state);

    bool is_session_state_expect(const SessionState &expect) const;

    static bool is_continue_recv(const Result<ProcResult, StatusCode> &result);
    static bool is_continue_recv(const Result<ProcResult, std::string> &result);
    static bool is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result);
    static bool is_executing_cgi(const Result<ProcResult, StatusCode> &result);
    static bool is_executing_cgi(const Result<ProcResult, std::string> &result);
    static bool is_connection_closed(const Result<ProcResult, std::string> &result);

    SessionResult process_client_event();
    SessionResult process_file_event();

    time_t cgi_timeout_limit() const;

    void close_client_fd();
    void clear_request();
    void clear_response();
    void kill_cgi_process();
    void clear_cgi();
    void close_cgi_read_fd();
    void close_cgi_write_fd();

    static AddressPortPair get_client_listen(const struct sockaddr_storage &client_addr);
    const char *session_state_char();
    static const char *session_state_char(const SessionState &state);

 private:
    int socket_fd_;
    int client_fd_;

    const Config &config_;
    ServerInfo server_info_;
    ServerConfig server_config_;
    AddressPortPair address_port_pair_;

    SessionState session_state_;

    HttpRequest *request_;  // todo: ptr; tmp & delete for next session
    HttpResponse *response_;  // todo: ptr; tmp & delete for next session

    std::size_t request_max_body_size_;

    AddressPortPair client_listen_;

    ProcResult recv_http_request();
    ProcResult send_http_response();

    ProcResult parse_http_request();
    ProcResult create_http_response();

    ProcResult execute_each_method();
    Result<AddressPortPair, std::string> get_address_port_pair() const;
    Result<ServerConfig, std::string> get_server_config() const;
    SessionResult get_host_config();
    SessionResult recv_cgi_result();

    ClientSession(const ClientSession &other);
    ClientSession &operator=(const ClientSession &rhs);
};
