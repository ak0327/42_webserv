#pragma once

# include <string>
# include <vector>
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Configuration.hpp"
# include "HttpRequest.hpp"
# include "HttpResponse.hpp"
# include "Result.hpp"
# include "webserv.hpp"

enum SessionState {
    kSessionInit,
    kAccepted,
    kReadingRequest,
    kCreatingResponse,
    kCreatingResponseBody,
    kCreatingCGIBody,
    kReadingFile,
    kExecutingCGI,
    kSendingResponse,
    kSessionCompleted,
    kSessionError
};

typedef Result<int, std::string> SessionResult;

class ClientSession {
 public:
    ClientSession(int socket_fd,
                  int client_fd,
                  const AddressPortPair &client_listen,
                  const Configuration &config);

    ~ClientSession();

    int get_client_fd() const;
    int get_cgi_fd() const;
    SessionState get_session_state() const;

    void set_session_state(const SessionState &set_state);

    bool is_session_state_expect_to(const SessionState &expect) const;

    SessionResult process_client_event();
    SessionResult process_file_event();

    void close_file_fd();
    void close_client_fd();
    void clear_request();
    void clear_response();

    static AddressPortPair get_client_listen(const struct sockaddr_storage &client_addr);

 private:
    int socket_fd_;
    int client_fd_;

    const Configuration &config_;
    ServerInfo server_info_;
    ServerConfig server_config_;

    SessionState session_state_;

    HttpRequest *request_;  // todo: ptr; tmp & delete for next session
    HttpResponse *response_;  // todo: ptr; tmp & delete for next session

    std::string recv_message_;
    // std::vector<unsigned char> recv_message_;  // todo
    // std::vector<unsigned char> data_; -> request, response
    std::size_t request_max_body_size_;

    AddressPortPair client_listen_;

    Result<std::string, std::string> recv_request();
    Result<int, int> send_response();

    Result<int, int> parse_http_request();
    Result<int, int> create_http_response();
    Result<AddressPortPair, std::string> get_address_port_pair() const;
    Result<ServerConfig, std::string> get_server_config() const;
    SessionResult update_config_params();
    SessionResult recv_cgi_result();

    ClientSession(const ClientSession &other);
    ClientSession &operator=(const ClientSession &rhs);
};
