#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <stdio.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <iostream>

int test_socket(const char *server_ip, const char *server_port) {
	int errcode;
	int socket_fd;
	int ai_family, ai_socktype, ai_protocol;
	struct addrinfo *addr_info;
	struct addrinfo	hints = {};
//	const char *server_ip = "127.0.0.1";
//	const char *server_port = "65536";

	printf("ip:%s, port:%s\n", server_ip, server_port);

	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_UNSPEC;  // allows IPv4 and IPv6
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;  // socket, IP, PORT
	hints.ai_protocol = IPPROTO_TCP;

	errcode = getaddrinfo(server_ip, server_port, &hints, &addr_info);
	if (errcode != 0) {
		std::cerr << "[Error] getaddrinfo:" << gai_strerror(errcode) << std::endl;
		return 1;
	}
//	std::cout << "errcode:" << errcode << ", " <<

	ai_family = addr_info->ai_family;
	ai_socktype = addr_info->ai_socktype;
	ai_protocol = addr_info->ai_protocol;
	errno = 0;
	std::cout << "socket" << std::endl;
	socket_fd = socket(ai_family, ai_socktype, ai_protocol);
	if (socket_fd == -1) {
		std::cerr << "[Error] socket:" << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "bind" << std::endl;
	errno = 0;
	if (bind(socket_fd, addr_info->ai_addr, addr_info->ai_addrlen) == -1) {
		std::cerr << "[Error] bind:" << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "listen" << std::endl;
	if (listen(socket_fd, SOMAXCONN) == -1) {
		std::cerr << "[Error] listen:" << strerror(errno) << std::endl;
		return 1;
	}

	std::cout << "OK" << std::endl;
	return 0;
}

// port 0, 0はエラーにならない
int main() {
	int ret1 = test_socket("255.255.255.254", "8080");
	int ret2 = test_socket("255.255.255.254", "8080");

	std::cout << "ret1:" << ret1 << std::endl;
	std::cout << "ret2:" << ret2 << std::endl;
}
