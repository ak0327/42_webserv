#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "webserv.hpp"
#include "Socket.hpp"
#include "Color.hpp"

static struct sockaddr_in create_addr();
static int create_nonblock_client_fd();

/* *********************** */
/*     Socket Unit Test    */
/* *********************** */
TEST(SocketUnitTest, DefaultConstructor) {
	Socket socket = Socket();

	EXPECT_EQ(OK, socket.get_status());
}

TEST(SocketUnitTest, ConstructorWithArgument) {
	Socket socket = Socket(SERVER_IP, SERVER_PORT);

	EXPECT_EQ(OK, socket.get_status());

}

// TEST(SocketUnitTest, CopyConstructor) {
// 	Socket socket_src = Socket(SERVER_IP, SERVER_PORT);
// 	Socket socket_new = Socket(socket_src);
//
// 	EXPECT_EQ(socket_src.get_status(), socket_new.get_status());
// 	EXPECT_EQ(socket_src.get_socket_fd(), socket_new.get_socket_fd());
// 	EXPECT_EQ(socket_src.get_server_port(), socket_new.get_server_port());
// 	EXPECT_EQ(socket_src.get_server_ip(), socket_new.get_server_ip());
// }
//
// TEST(SocketUnitTest, CopyAssignmentConstructor) {
// 	Socket socket_src = Socket(SERVER_IP, SERVER_PORT);
// 	Socket socket_new = socket_src;
//
// 	EXPECT_EQ(socket_src.get_status(), socket_new.get_status());
// 	EXPECT_EQ(socket_src.get_socket_fd(), socket_new.get_socket_fd());
// 	EXPECT_EQ(socket_src.get_server_port(), socket_new.get_server_port());
// 	EXPECT_EQ(socket_src.get_server_ip(), socket_new.get_server_ip());
// }

TEST(SocketUnitTest, ConstructorWithValidServerIP) {
	int port = 49152;
	Socket socket1 = Socket("127.0.0.1", std::to_string(port++).c_str());
	Socket socket2 = Socket("0.0.0.0", std::to_string(port++).c_str());
	Socket socket3 = Socket("000.0000.00000.000000", std::to_string(port++).c_str());

	EXPECT_EQ(OK, socket1.get_status());
	EXPECT_EQ(OK, socket2.get_status());
	EXPECT_EQ(OK, socket3.get_status());

}

TEST(SocketUnitTest, ConstructorWithInvalidServerIP) {
	int port = 49152;
	Socket socket1 = Socket("127.0.0.0.1", std::to_string(port++).c_str());
	Socket socket2 = Socket("256.0.0.0", std::to_string(port++).c_str());
	Socket socket3 = Socket("-1", std::to_string(port++).c_str());
	Socket socket4 = Socket("a.0.0.0", std::to_string(port++).c_str());
	Socket socket5 = Socket("127:0.0.1", std::to_string(port++).c_str());
	Socket socket6 = Socket("127,0.0.1", std::to_string(port++).c_str());
	Socket socket7 = Socket("127.0.0.-1", std::to_string(port++).c_str());
	Socket socket8 = Socket("2147483647.2147483647.2147483647.2147483647", std::to_string(port++).c_str());
	// Socket socket9 = Socket("", std::to_string(port++).c_str());  todo: ok?
	Socket socket10 = Socket("hoge", std::to_string(port++).c_str());
	Socket socket11 = Socket("0001.0001.0001.0001", std::to_string(port++).c_str());
	Socket socket12 = Socket("255.255.255.254", std::to_string(port++).c_str());
	// Socket socket13 = Socket("255.255.255.255", std::to_string(port++).c_str());  // Linux OK, todo:error?

	EXPECT_EQ(ERROR, socket1.get_status());
	EXPECT_EQ(ERROR, socket2.get_status());
	EXPECT_EQ(ERROR, socket3.get_status());
	EXPECT_EQ(ERROR, socket4.get_status());
	EXPECT_EQ(ERROR, socket5.get_status());
	EXPECT_EQ(ERROR, socket6.get_status());
	EXPECT_EQ(ERROR, socket7.get_status());
	EXPECT_EQ(ERROR, socket8.get_status());
	// EXPECT_EQ(ERROR, socket9.get_status());
	EXPECT_EQ(ERROR, socket10.get_status());
	EXPECT_EQ(ERROR, socket11.get_status());
	EXPECT_EQ(ERROR, socket12.get_status());
	// EXPECT_EQ(ERROR, socket13.get_status());
}

TEST(SocketUnitTest, ConstructorWithValidServerPort) {
	Socket socket1 = Socket(SERVER_IP, "0");  // ephemeral port
	Socket socket2 = Socket(SERVER_IP, "0000");
	Socket socket3 = Socket(SERVER_IP, "8080");
	Socket socket4 = Socket(SERVER_IP, "65535");

	EXPECT_EQ(OK, socket1.get_status());
	EXPECT_EQ(OK, socket2.get_status());
	EXPECT_EQ(OK, socket3.get_status());
	EXPECT_EQ(OK, socket4.get_status());
}

TEST(SocketUnitTest, ConstructorWithInvalidServerPort) {
	Socket socket1 = Socket(SERVER_IP, "-1");
//	Socket socket2 = Socket(SERVER_IP, "65536");  // uisingned short 65536->0(ephemeral port)
	// Socket socket3 = Socket(SERVER_IP, "");	// strtol->0 (tmp)
	Socket socket4 = Socket(SERVER_IP, "hoge");
	Socket socket5 = Socket(SERVER_IP, "--123123");
	Socket socket6 = Socket(SERVER_IP, "127.1");

	EXPECT_EQ(ERROR, socket1.get_status());
//	EXPECT_EQ(ERROR, socket2.get_status());
	// EXPECT_EQ(ERROR, socket3.get_status());
	EXPECT_EQ(ERROR, socket4.get_status());
	EXPECT_EQ(ERROR, socket5.get_status());
	EXPECT_EQ(ERROR, socket6.get_status());
}

TEST(SocketUnitTest, Getter) {
	Socket socket = Socket();

	EXPECT_EQ(OK, socket.get_status());
	EXPECT_NE(ERROR, socket.get_socket_fd());
}

// TEST(SocketUnitTest, ExceedMaxFd) {
// 	int limit = 20;
//
// 	struct rlimit old_limits;
// 	if (getrlimit(RLIMIT_NOFILE, &old_limits) != 0) {
// 		std::cerr << "getrlimit failed\n";
// 		return;
// 	}
// 	printf("old_limit.cur:%llu,\n", old_limits.rlim_cur);
//
// 	struct rlimit new_limits;
// 	new_limits.rlim_cur = limit;
// 	new_limits.rlim_max = old_limits.rlim_max;
//
// 	printf("new_limit.cur:%llu\n", new_limits.rlim_cur);
//
// 	if (setrlimit(RLIMIT_NOFILE, &new_limits) != 0) {
// 		std::cerr << "setrlimit failed\n";
// 		return;
// 	}
//
// 	int min_fd = 3;
// 	std::vector<Socket> sockets;
// 	for (int i = 0; i < limit + 10; ++i) {
// 		// Socket socket = Socket(SERVER_IP, std::to_string(49152 + i).c_str());
// 		// sockets.push_back(socket);
// 		// sockets[i] = Socket(SERVER_IP, std::to_string(49152 + i).c_str());
// 		sockets.push_back(Socket(SERVER_IP, std::to_string(49152 + i).c_str()));
// 		printf("%si:%d, fd:%d, status:%d%s\n", YELLOW, i, sockets[i].get_socket_fd(), sockets[i].get_status(), RESET);
//
// 		if (i + min_fd <= limit) {
// 			EXPECT_EQ(OK, sockets[i].get_status());
// 			EXPECT_NE(ERROR, sockets[i].get_socket_fd());
// 		} else {
// 			EXPECT_EQ(ERROR, sockets[i].get_status());
// 			EXPECT_EQ(ERROR, sockets[i].get_socket_fd());
// 		}
// 	}
//
// 	if (setrlimit(RLIMIT_NOFILE, &old_limits) != 0) {
// 		std::cerr << "Restoring setrlimit failed\n";
// 		return;
// 	}
//
// 	printf("old_limit.cur:%llu\n", old_limits.rlim_cur);
// }

/* *********************** */
/* Socket Integration Test */
/* *********************** */
TEST(SocketIntegrationTest, ConnectToClient) {
	Socket server;

	EXPECT_EQ(server.get_status(), OK);
	EXPECT_NE(server.get_socket_fd(), ERROR);

	int client_fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(std::strtol(SERVER_PORT, NULL, 10));
	addr.sin_addr.s_addr = inet_addr(SERVER_IP);

	EXPECT_EQ(connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)), OK);

	close(client_fd);
}

TEST(SocketIntegrationTest, ConnectTooManyClient) {
	Socket server;
	int client_fd;

	EXPECT_EQ(OK, server.get_status());
	EXPECT_NE(ERROR, server.get_socket_fd());

	// connect under SOMAXCONN
	std::vector<int> client_fds;
	for (int i = 0; i < SOMAXCONN; ++i) {
		client_fd = socket(AF_INET, SOCK_STREAM, 0);
		// printf("cnt:%d, client_fd:%d\n", i+1, client_fd);

		EXPECT_NE(ERROR, client_fd);

		if (client_fd != ERROR) {
			client_fds.push_back(client_fd);
			struct sockaddr_in addr = create_addr();

			EXPECT_EQ(OK, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));
		}
	}

	// connect over SOMAXCONN -> fd set to nonblock
	client_fd = create_nonblock_client_fd();
	// printf("cnt:%d, client_fd:%d\n", SOMAXCONN, client_fd);

	EXPECT_NE(ERROR, client_fd);

	if (client_fd != ERROR) {
		client_fds.push_back(client_fd);
		struct sockaddr_in addr = create_addr();

		EXPECT_EQ(ERROR, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));
	}

	// destruct
	for (std::vector<int>::iterator itr = client_fds.begin(); itr != client_fds.end(); ++itr) {
		close(*itr);
	}
	client_fds.clear();
}

/* helper funcs */
static struct sockaddr_in create_addr() {
	struct sockaddr_in addr = {};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	addr.sin_port = htons(std::strtol(SERVER_PORT, NULL, 10));
	return addr;
}

static int create_nonblock_client_fd() {
	int client_fd;
	int result_fcntl;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_fd == ERROR) {
		return ERROR;
	}
	result_fcntl = fcntl(client_fd, F_SETFL, O_NONBLOCK);
	if (result_fcntl == ERROR) {
		close(client_fd);
		return ERROR;
	}
	return client_fd;
}
