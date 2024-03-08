#pragma once

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string>
#include "webserv.hpp"
#include "Socket.hpp"

class Client {
 public:
	Client(const char *server_ip, const char *server_port);
	~Client();

	std::string get_recv_message() const;
    void send_msg(const std::string &send_msg) const;
    void recv_msg(std::size_t bufsize);

 private:
	// struct sockaddr_in addr_;

    Socket *socket_;
	int connect_fd_;
	std::string recv_message_;
};
