#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include "webserv.hpp"

class Client {
 public:
	Client(const char *server_ip, const char *server_port);
	~Client();

	std::string get_recv_message() const;
	void process_server_connect(const std::string &send_msg);

 private:
	int connect_fd_;
	std::string recv_message_;
	struct sockaddr_in addr_;
};
