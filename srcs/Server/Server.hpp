#pragma once

# include <string>
# include <vector>
# include "webserv.hpp"
# include "Constant.hpp"
# include "HttpRequest.hpp"
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

class Server {
 public:
	explicit Server(const Config &config);
	~Server();

	void process_client_connection();
	std::string get_recv_message() const;  // todo: for test, debug

 private:
	Socket _socket;
	std::string _recv_message;  // for test. this variable valid only connect with 1 client
	IOMultiplexer *_fds;

	Result<int, std::string> communicate_with_client(int ready_fd);
	Result<int, std::string> accept_and_store_connect_fd();
	Result<int, std::string> communicate_with_ready_client(int ready_fd);
};
