#pragma once

# include <deque>
# include <map>
# include <string>
# include <vector>
# include "webserv.hpp"
# include "ClientSession.hpp"
# include "Constant.hpp"
# include "ConfigStruct.hpp"
# include "Configuration.hpp"
# include "HttpRequest.hpp"
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

typedef Result<int, std::string> ServerResult;
typedef int Fd;

class Server {
 public:
	explicit Server(const Configuration &config);
	~Server();

    ServerResult init();
	ServerResult run();
    void set_timeout(int timeout_msec);

 private:
	std::map<Fd, Socket *> sockets_;
	IOMultiplexer *fds_;

    std::deque<Fd> socket_fds_;
    std::deque<Fd> client_fds_;

    std::map<Fd, ClientSession *> sessions_;

    const Configuration &config_;

	ServerResult accept_connect_fd(int socket_fd, struct sockaddr_storage *client_addr);
    ServerResult communicate_with_client(int ready_fd);
    ServerResult create_session(int socket_fd);
    ServerResult process_session(int ready_fd);

    static Result<Socket *, std::string> create_socket(const std::string &address,
                                                       const std::string &port);
    ServerResult create_sockets(const Configuration &config);
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds();

    bool is_socket_fd(int fd) const;
    void delete_sockets();
    void delete_session(std::map<Fd, ClientSession *>::iterator session);
    void delete_sessions();
    void close_client_fd(int fd);
    void update_fd_type(int fd,
                        FdType update_from,
                        FdType update_to);
    void init_session(ClientSession *session);
};
