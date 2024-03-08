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
# include "Session.hpp"
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
    ServerResult echo();
    void set_io_timeout();

 private:
	std::map<SocketFd, Socket *> sockets_;
	IOMultiplexer *fds_;

    std::deque<SocketFd> socket_fds_;
    std::deque<ClientFd> client_fds_;

    std::map<ClientFd, Event *> client_events_;
    std::map<CgiFd, Event *> cgi_events_;  // Event*: client_event

    std::set<FdTimeoutLimitPair> cgi_time_manager_;
    std::set<FdTimeoutLimitPair> active_client_time_manager_;
    std::set<FdTimeoutLimitPair> idling_client_time_manager_;  // keepalive


    std::map<std::string, Session> sessions_;

    const Config &config_;

    bool echo_mode_on_;


	ServerResult accept_connect_fd(int socket_fd, struct sockaddr_storage *client_addr);
    ServerResult create_event(int socket_fd);
    ServerResult process_event(int ready_fd);

    void idling_event(Event *event);
    void clear_events();

    void update_fd_type(int fd, FdType update_from, FdType update_to);
    static Result<Socket *, std::string> create_socket(const std::string &address,
                                                       const std::string &port);
    ServerResult create_sockets(const Config &config);
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds();

    void management_timeout_events();
    void register_cgi_write_fd_to_event_manager(Event **client_event);
    void register_cgi_read_fd_to_event_manager(Event **client_event);
    void register_cgi_fds_to_event_manager(Event **client_event);
    void clear_fd_from_event_manager(int fd);
    void clear_cgi_fds_from_event_manager(const Event &cgi_event);
    void erase_from_timeout_manager(int cgi_fd);

    void management_cgi_executing_timeout(time_t current_time);
    void management_active_client_timeout(time_t current_time);
    void management_idling_client_timeout(time_t current_time);

    bool is_idling_client(int fd);
    void clear_from_keepalive_clients(int client_fd);
    static std::set<FdTimeoutLimitPair>::iterator find_fd_in_timeout_pair(int fd, const std::set<FdTimeoutLimitPair> &pair);
    static AddressPortPair get_client_listen(const struct sockaddr_storage &client_addr);

    bool is_socket_fd(int fd) const;
    bool is_fd_type_expect(int fd, const FdType &type);
    void delete_sockets();
    void delete_event(std::map<Fd, Event *>::iterator event);
    void close_client_fd(int fd);
    void update_fd_type_read_to_write(const EventPhase &event_state, int fd);

    bool is_client_fd(int fd);
    bool is_cgi_fd(int fd);
    ServerResult handle_client_event(int client_fd);
    ServerResult handle_cgi_event(int cgi_fd);

    bool is_already_managed(int fd);
    void handle_active_client_timeout(Event *client_event);
    void clear_from_active_client_manager(int fd);
};
