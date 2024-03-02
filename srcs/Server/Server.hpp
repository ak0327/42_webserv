#pragma once

# include <deque>
# include <map>
# include <set>
# include <string>
# include <utility>
# include <vector>
# include "webserv.hpp"
# include "Event.hpp"
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Config.hpp"
# include "HttpRequest.hpp"
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

typedef Result<int, std::string> ServerResult;
typedef Fd SocketFd;
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
    void set_io_timeout(int timeout_msec);

 private:
	std::map<SocketFd, Socket *> sockets_;
	IOMultiplexer *fds_;

    std::deque<SocketFd> socket_fds_;
    std::deque<ClientFd> client_fds_;
    std::set<FdTimeoutLimitPair> cgi_fds_;

    std::map<ClientFd, Event *> client_events_;
    std::map<CgiFd, Event *> cgi_events_;

    const Config &config_;

	ServerResult accept_connect_fd(int socket_fd, struct sockaddr_storage *client_addr);
    ServerResult communicate_with_client(int ready_fd);
    ServerResult create_event(int socket_fd);
    ServerResult process_event(int ready_fd);

    void init_event(Event *event);
    void clear_event();

    void update_fd_type(int fd, FdType update_from, FdType update_to);
    static Result<Socket *, std::string> create_socket(const std::string &address,
                                                       const std::string &port);
    ServerResult create_sockets(const Config &config);
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds();

    void management_timeout_events();
    void register_cgi_write_fd_to_event_manager(Event **cgi_event);
    void register_cgi_read_fd_to_event_manager(Event **cgi_event);
    void clear_fd_from_event_manager(int fd);

    void clear_cgi_fd_from_event_manager(int fd);
    void erase_from_timeout_manager(int cgi_fd);

    bool is_socket_fd(int fd) const;
    bool is_fd_type_expect(int fd, const FdType &type);
    void delete_sockets();
    void delete_event(std::map<Fd, Event *>::iterator event);
    void close_client_fd(int fd);
    void update_fd_type_read_to_write(const EventState &event_state, int fd);

    bool is_ready_to_send_response(const Event &event);
    bool is_sending_request_body_to_cgi(const Event &event);
    bool is_receiving_cgi_response(const Event &event);
    bool is_cgi_execute_completed(const Event &event);
    bool is_event_creating_response_body(const Event &event);
    bool is_event_completed(const Event &event);
    bool is_event_error_occurred(const Event &event);
};
