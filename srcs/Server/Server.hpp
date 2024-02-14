#pragma once

# include <deque>
# include <map>
# include <string>
# include <vector>
# include "webserv.hpp"
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

	void process_client_connection();
	std::string get_recv_message() const;  // todo: for test, debug

 private:
	std::map<Fd, Socket *> sockets_;
	std::string recv_message_;  // for test. this variable valid only connect with 1 client
	IOMultiplexer *fds_;

    std::deque<int> socket_fds_;
    std::deque<int> client_fds_;

    ServerResult communicate_with_client(int ready_fd);
	ServerResult accept_connect_fd(int socket_fd);
	ServerResult communicate_with_ready_client(int connect_fd);

    ServerResult create_sockets(const Configuration &config);
    Result<IOMultiplexer *, std::string> create_io_multiplexer_fds();

    bool is_socket_fd(int fd) const;
    void delete_sockets();
    void close_client_fds();
};
