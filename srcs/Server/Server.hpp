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
	explicit Server(const Configuration &config) throw();
	~Server() throw();

    ServerResult init() throw();
	ServerResult run() throw();
    void set_timeout(int timeout_msec) throw();

 private:
	std::map<Fd, Socket *> sockets_;
	IOMultiplexer *fds_;

    std::deque<Fd> socket_fds_;
    std::deque<Fd> client_fds_;

    std::map<Fd, ClientSession *> sessions_;

    const Configuration &config_;

	ServerResult accept_connect_fd(int socket_fd, struct sockaddr_storage *client_addr) throw();
    ServerResult communicate_with_client(int ready_fd) throw();
    ServerResult create_session(int socket_fd) throw();
    ServerResult process_session(int ready_fd) throw();

    static Result<Socket *, std::string> create_socket(const std::string &address,
                                                       const std::string &port) throw();
    ServerResult create_sockets(const Configuration &config) throw();
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds() throw();

    bool is_socket_fd(int fd) const throw();
    void delete_sockets() throw();
    void close_client_fds() throw();
    void close_client_fd(int fd) throw();
    void update_fd_type_read_to_write(const SessionState &session_state, int fd) throw();
};
