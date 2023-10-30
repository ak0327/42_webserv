#pragma once

# include <string>

// Mock -> gmock ??
////////////////////////////////////////////////
# include "HttpRequest.hpp"
# define TEST_RESPONSE_MSG	"test response"

class Config {
 public:
	Config()
		: ip_("127.0.0.1"), port_("8080") {};
	Config(const std::string &config_file_path)
		: ip_("127.0.0.1"), port_("8080") { (void)config_file_path; };
	~Config() {};

	void set_ip(const std::string &ip) { ip_ = ip; }
	void set_port(const std::string &port) { port_ = port; }
	std::string get_server_ip() const { return ip_; }
	std::string get_server_port() const { return port_; }

 private:
	std::string ip_;
	std::string port_;
};

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

std::string get_valid_config_file_path(const char *path);
