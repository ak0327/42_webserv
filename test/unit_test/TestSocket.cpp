#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Constant.hpp"
#include "Socket.hpp"

namespace {

const char *SERVER_IP = "127.0.0.1";
const char *SERVER_PORT = "8080";

struct sockaddr_in create_addr() {
	struct sockaddr_in addr = {};

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(SERVER_IP);
	addr.sin_port = htons(std::strtol(SERVER_PORT, NULL, 10));
	return addr;
}

int create_nonblock_client_fd() {
	int client_fd;
	int result_fcntl;

	client_fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client_fd == INIT_FD) {
		return ERR;
	}
	result_fcntl = fcntl(client_fd, F_SETFL, O_NONBLOCK);
	if (result_fcntl == ERR) {
		close(client_fd);
		return ERR;
	}
	return client_fd;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

/* ******************************************* */
/*               Socket Unit Test              */
/* ******************************************* */
TEST(SocketUnitTest, ConstructorWithArgument) {
	Socket socket = Socket(SERVER_IP, SERVER_PORT);

	EXPECT_EQ(true, socket.is_socket_success());

}

TEST(SocketUnitTest, ConstructorWithValidServerIP) {
	int port = 49152;
	Socket socket1 = Socket("127.0.0.1", std::to_string(port++).c_str());
	Socket socket2 = Socket("0.0.0.0", std::to_string(port++).c_str());
	Socket socket3 = Socket("000.0000.00000.000000", std::to_string(port++).c_str());

	EXPECT_EQ(true, socket1.is_socket_success());
	EXPECT_EQ(true, socket2.is_socket_success());
	EXPECT_EQ(true, socket3.is_socket_success());

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

	EXPECT_EQ(false, socket1.is_socket_success());
	EXPECT_EQ(false, socket2.is_socket_success());
	EXPECT_EQ(false, socket3.is_socket_success());
	EXPECT_EQ(false, socket4.is_socket_success());
	EXPECT_EQ(false, socket5.is_socket_success());
	EXPECT_EQ(false, socket6.is_socket_success());
	EXPECT_EQ(false, socket7.is_socket_success());
	EXPECT_EQ(false, socket8.is_socket_success());
	// EXPECT_EQ(false, socket9.is_socket_success());
	EXPECT_EQ(false, socket10.is_socket_success());
	EXPECT_EQ(false, socket11.is_socket_success());
	EXPECT_EQ(false, socket12.is_socket_success());
	// EXPECT_EQ(false, socket13.is_socket_success());
}

TEST(SocketUnitTest, ConstructorWithValidServerPort) {
	Socket socket1 = Socket(SERVER_IP, "0");  // ephemeral port
	Socket socket2 = Socket(SERVER_IP, "0000");
	Socket socket3 = Socket(SERVER_IP, "8080");
	Socket socket4 = Socket(SERVER_IP, "65535");

	EXPECT_EQ(true, socket1.is_socket_success());
	EXPECT_EQ(true, socket2.is_socket_success());
	EXPECT_EQ(true, socket3.is_socket_success());
	EXPECT_EQ(true, socket4.is_socket_success());
}

TEST(SocketUnitTest, ConstructorWithInvalidServerPort) {
	Socket socket1 = Socket(SERVER_IP, "-1");
//	Socket socket2 = Socket(SERVER_IP, "65536");  // uisingned short 65536->0(ephemeral port)
	// Socket socket3 = Socket(SERVER_IP, "");	// strtol->0 (tmp)
	Socket socket4 = Socket(SERVER_IP, "hoge");
	Socket socket5 = Socket(SERVER_IP, "--123123");
	Socket socket6 = Socket(SERVER_IP, "127.1");

	EXPECT_EQ(false, socket1.is_socket_success());
//	EXPECT_EQ(false, socket2.is_socket_success());
	// EXPECT_EQ(false, socket3.is_socket_success());
	EXPECT_EQ(false, socket4.is_socket_success());
	EXPECT_EQ(false, socket5.is_socket_success());
	EXPECT_EQ(false, socket6.is_socket_success());
}

TEST(SocketUnitTest, Getter) {
	Socket socket = Socket("", "");

	EXPECT_EQ(false, socket.is_socket_success());
	EXPECT_EQ(INIT_FD, socket.get_socket_fd());
}


/* ******************************************* */
/*           Socket Integration Test           */
/* ******************************************* */
TEST(SocketIntegrationTest, ConnectToClient) {
	try {
		Socket server = Socket(SERVER_IP, SERVER_PORT);
		struct sockaddr_in addr = {};
		int client_fd;

		EXPECT_EQ(true, server.is_socket_success());
		EXPECT_NE(INIT_FD, server.get_socket_fd());

		client_fd = socket(AF_INET, SOCK_STREAM, 0);
		addr = create_addr();
		EXPECT_EQ(OK, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));

		close(client_fd);
	} catch (std::exception const &e) {
		FAIL();
	}
}

TEST(SocketIntegrationTest, ConnectOverSomaxconClient) {
	try {
		Socket server = Socket(SERVER_IP, SERVER_PORT);
		int client_fd;
		struct sockaddr_in addr = {};

		EXPECT_EQ(true, server.is_socket_success());
		EXPECT_NE(INIT_FD, server.get_socket_fd());

		/* connect under SOMAXCONN */
		std::vector<int> client_fds;
		for (int i = 0; i < SOMAXCONN; ++i) {
			client_fd = socket(AF_INET, SOCK_STREAM, 0);
			// printf("cnt:%d, client_fd:%d\n", i+1, client_fd);

			EXPECT_NE(INIT_FD, client_fd);

			if (client_fd != INIT_FD) {
				client_fds.push_back(client_fd);
				addr = create_addr();

				EXPECT_EQ(OK, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));
			}
		}

		/* connect over SOMAXCONN -> fd set to nonblock */
		client_fd = create_nonblock_client_fd();
		// printf("cnt:%d, client_fd:%d\n", SOMAXCONN, client_fd);

		EXPECT_NE(INIT_FD, client_fd);

		if (client_fd != INIT_FD) {
			client_fds.push_back(client_fd);
			addr = create_addr();

			EXPECT_EQ(ERR, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));
		}

		/* destruct */
		for (std::vector<int>::iterator itr = client_fds.begin(); itr != client_fds.end(); ++itr) {
			close(*itr);
		}
		client_fds.clear();
	} catch (std::exception const &e) {
		FAIL();
	}
}
