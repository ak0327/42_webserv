#pragma once

# include <deque>
# include <map>
# include <set>
# include <string>
# include <utility>
# include <vector>
# include "webserv.hpp"
# include "ClientSession.hpp"
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Config.hpp"
# include "HttpRequest.hpp"
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

typedef Result<int, std::string> ServerResult;
typedef Fd ClientFd;
typedef Fd CgiFd;
typedef std::pair<time_t, Fd> FdTimeoutLimitPair;


class Server {
 public:
	explicit Server(const Config &config);
	~Server();

    ServerResult init();
	ServerResult run();
    ServerResult echo();  // todo: implement echo for test
    void set_timeout(int timeout_msec);

 private:
	std::map<Fd, Socket *> sockets_;
	IOMultiplexer *fds_;

    std::deque<Fd> socket_fds_;
    std::deque<Fd> client_fds_;
    std::set<FdTimeoutLimitPair> cgi_fds_;

    std::map<Fd, ClientSession *> client_sessions_;
    std::map<Fd, ClientSession *> cgi_sessions_;

    const Config &config_;

	ServerResult accept_connect_fd(int socket_fd, struct sockaddr_storage *client_addr);
    ServerResult communicate_with_client(int ready_fd);
    ServerResult create_session(int socket_fd);
    ServerResult process_session(int ready_fd);

    void init_session(ClientSession *session);
    void clear_sessions();

    void update_fd_type(int fd, FdType update_from, FdType update_to);
    static Result<Socket *, std::string> create_socket(const std::string &address,
                                                       const std::string &port);
    ServerResult create_sockets(const Config &config);
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds();

    void management_timeout_sessions();
    void register_cgi_write_fd_to_event_manager(ClientSession **client);
    void register_cgi_read_fd_to_event_manager(ClientSession **client);
    void clear_fd_from_event_manager(int fd);

    void clear_cgi_fd_from_event_manager(int fd);
    void erase_from_timeout_manager(int cgi_fd);
    std::set<FdTimeoutLimitPair>::iterator get_timeout_cgi();

    bool is_socket_fd(int fd) const;
    bool is_fd_type_expect(int fd, const FdType &type);
    void delete_sockets();
    void delete_session(std::map<Fd, ClientSession *>::iterator session);
    void close_client_fd(int fd);
    void update_fd_type_read_to_write(const SessionState &session_state, int fd);

    bool is_ready_to_send_response(const ClientSession &client);
    bool is_sending_request_body_to_cgi(const ClientSession &client);
    bool is_receiving_cgi_response(const ClientSession &client);
    bool is_cgi_execute_completed(const ClientSession &client);
    bool is_session_creating_response_body(const ClientSession &client);
    bool is_session_completed(const ClientSession &client);
    bool is_session_error_occurred(const ClientSession &client);
};
