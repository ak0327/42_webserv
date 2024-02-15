#pragma once

# include <string>
# include <vector>
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Configuration.hpp"
# include "HttpRequest.hpp"

# include "Result.hpp"
# include "webserv.hpp"

enum SessionState {
    kSessionInit,
    kAccepted,
    kReadingRequest,
    kCreatingResponse,
    kReadingFile,
    kExecutingCGI,
    kSendingResponse,
    kCompleted
};

typedef Result<int, std::string> SessionResult;

class ClientSession {
 public:
    ClientSession(int socket_fd,
                  int client_fd,
                  const Configuration &config);

    ~ClientSession();

    int get_client_fd() const;
    int get_file_fd() const;
    SessionState get_session_state() const;
    bool is_session_completed() const;

    SessionResult process_client_event();
    SessionResult process_file_event();

    void close_file_fd();

 private:
    int socket_fd_;
    int client_fd_;
    int file_fd_;

    ServerInfo server_info_;
    ServerConfig *server_config_;
    const Configuration &config_;

    SessionState session_state_;

    std::string recv_message_;
    // std::vector<unsigned char> recv_message_;  // todo
    std::vector<unsigned char> data_;
    std::size_t body_size_;

    HttpRequest *http_request_;  // todo: ptr; tmp
    HttpResponse *http_response_;  // todo: ptr; tmp

    Result<std::string, std::string> recv_request();
    SessionResult send_response();


    ClientSession(const ClientSession &other);
    ClientSession &operator=(const ClientSession &rhs);
};
