#pragma once

# include <string>
# include <vector>
# include "Constant.hpp"
# include "HttpRequest.hpp"
# include "IOMultiplexer.hpp"
# include "Result.hpp"
# include "Socket.hpp"

# define TEST_RESPONSE_MSG	"test response"

// Mock -> gmock ??
////////////////////////////////////////////////
class HttpResponse {
 public:
	std::string _response_message;

	explicit HttpResponse(const HttpRequest &request) {
		int status = request.get_status_code();
		std::string message;

		if (status == STATUS_BAD_REQUEST) {
			message = "400 BAD REQUEST";
		} else if (status == STATUS_SERVER_ERROR) {
			message = "500 SERVER ERROR";
		} else {
			message = "200 OK";
		}
		_response_message = message;
	}

	char *get_response_message() const { return const_cast<char *>(_response_message.c_str()); }
	size_t get_response_size() const { return _response_message.size(); }
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
