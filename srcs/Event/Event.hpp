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

enum EventPhase {
    kEventInit,

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

    kEventCompleted,
    kEventError
};


typedef Result<ProcResult, std::string> EventResult;

class Event {
 public:
    Event(int socket_fd,
          int client_fd,
          const AddressPortPair &client_listen,
          const Config &config);

    ~Event();

    int client_fd() const;
    int cgi_read_fd() const;
    int cgi_write_fd() const;
    EventPhase event_phase() const;

    void set_event_phase(const EventPhase &set_phase);

    bool is_event_phase_expect(const EventPhase &expect) const;

    static bool is_continue_recv(const Result<ProcResult, StatusCode> &result);
    static bool is_continue_recv(const Result<ProcResult, std::string> &result);
    static bool is_read_conf_for_parse_body(const Result<ProcResult, StatusCode> &result);
    static bool is_executing_cgi(const Result<ProcResult, StatusCode> &result);
    static bool is_executing_cgi(const Result<ProcResult, std::string> &result);
    static bool is_connection_closed(const Result<ProcResult, std::string> &result);

    EventResult process_client_event();
    EventResult process_file_event();
    ProcResult exec_cgi();

    time_t cgi_timeout_limit() const;

    void close_client_fd();
    void clear_request();
    void clear_response();
    void kill_cgi_process();
    void clear_cgi();

    static AddressPortPair get_client_listen(const struct sockaddr_storage &client_addr);
    const char *event_phase_char();
    static const char *event_phase_char(const EventPhase &phase);
    static std::string event_phase_str(const EventPhase &phase);

 private:
    int socket_fd_;
    int client_fd_;

    const Config &config_;
    ServerInfo server_info_;
    ServerConfig server_config_;
    AddressPortPair address_port_pair_;

    EventPhase event_state_;

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
    EventResult get_host_config();
    EventResult recv_cgi_result();

    Event(const Event &other);
    Event &operator=(const Event &rhs);
};


std::ostringstream &operator<<(std::ostringstream &out, const Event &event);
