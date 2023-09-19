#pragma once

# include <string>
# include <vector>
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

# define TEST_RESPONSE_MSG	"test response"

// Mock -> gmock ??
////////////////////////////////////////////////
class HttpRequest {
 public:
	explicit HttpRequest(const std::string &msg) { (void)msg; }
};

class HttpResponse {
 public:
	explicit HttpResponse(HttpRequest request) { (void)request; }
	char *get_response_message() const { return const_cast<char *>(TEST_RESPONSE_MSG); }
	size_t get_response_size() const {
		return std::string(TEST_RESPONSE_MSG).size();
	}
};
////////////////////////////////////////////////

class Server {
 public:
	Server(const char *server_ip, const char *server_port);  // tmp
	// Server(const Config config);  // todo
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
