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
	Config config;
	config.set_ip(SERVER_IP); config.set_port(SERVER_PORT);

	Socket socket = Socket(config);

	EXPECT_TRUE(socket.is_socket_success());

}

TEST(SocketUnitTest, ConstructorWithValidServerIP) {
	int port = 49152;
	Config config;

	config.set_ip("127.0.0.1"); config.set_port(std::to_string(port++));
	Socket socket1 = Socket(config);

	config.set_ip("0.0.0.0"); config.set_port(std::to_string(port++));
	Socket socket2 = Socket(config);

	config.set_ip("000.0000.00000.000000"); config.set_port(std::to_string(port++));
	Socket socket3 = Socket(config);

	EXPECT_TRUE(socket1.is_socket_success());
	EXPECT_TRUE(socket2.is_socket_success());
	EXPECT_TRUE(socket3.is_socket_success());

}

TEST(SocketUnitTest, ConstructorWithInvalidServerIP) {
	int port = 49152;
	Config config;

	config.set_ip("127.0.0.0.1"); config.set_port(std::to_string(port++));
	Socket socket1 = Socket(config);

	config.set_ip("256.0.0.0"); config.set_port(std::to_string(port++));
	Socket socket2 = Socket(config);

	config.set_ip("-1"); config.set_port(std::to_string(port++));
	Socket socket3 = Socket(config);

	config.set_ip("a.0.0.0"); config.set_port(std::to_string(port++));
	Socket socket4 = Socket(config);

	config.set_ip("127:0.0.1"); config.set_port(std::to_string(port++));
	Socket socket5 = Socket(config);

	config.set_ip("127,0.0.1"); config.set_port(std::to_string(port++));
	Socket socket6 = Socket(config);

	config.set_ip("127.0.0.-1"); config.set_port(std::to_string(port++));
	Socket socket7 = Socket(config);

	config.set_ip("2147483647.2147483647.2147483647.2147483647"); config.set_port(std::to_string(port++));
	Socket socket8 = Socket(config);

	// config.set_ip(""); config.set_port(std::to_string(port++));
	// Socket socket9 = Socket("", std::to_string(port++).c_str());  todo: ok?

	config.set_ip("hoge"); config.set_port(std::to_string(port++));
	Socket socket10 = Socket(config);

	config.set_ip("0001.0001.0001.0001"); config.set_port(std::to_string(port++));
	Socket socket11 = Socket(config);

	config.set_ip("255.255.255.254"); config.set_port(std::to_string(port++));
	Socket socket12 = Socket(config);


	// config.set_ip("255.255.255.255"); config.set_port(std::to_string(port++));
	// Socket socket13 = Socket("255.255.255.255", std::to_string(port++).c_str());  // Linux OK, todo:error?

	EXPECT_FALSE(socket1.is_socket_success());
	EXPECT_FALSE(socket2.is_socket_success());
	EXPECT_FALSE(socket3.is_socket_success());
	EXPECT_FALSE(socket4.is_socket_success());
	EXPECT_FALSE(socket5.is_socket_success());
	EXPECT_FALSE(socket6.is_socket_success());
	EXPECT_FALSE(socket7.is_socket_success());
	EXPECT_FALSE(socket8.is_socket_success());
	// EXPECT_FALSE(socket9.is_socket_success());
	EXPECT_FALSE(socket10.is_socket_success());
	EXPECT_FALSE(socket11.is_socket_success());
	EXPECT_FALSE(socket12.is_socket_success());
	// EXPECT_FALSE(socket13.is_socket_success());
}

TEST(SocketUnitTest, ConstructorWithValidServerPort) {
	Config config;

	config.set_ip(SERVER_IP); config.set_port("0");
	Socket socket1 = Socket(config);  // ephemeral port

	config.set_ip(SERVER_IP); config.set_port("0000");
	Socket socket2 = Socket(config);

	config.set_ip(SERVER_IP); config.set_port("8080");
	Socket socket3 = Socket(config);

	config.set_ip(SERVER_IP); config.set_port("65535");
	Socket socket4 = Socket(config);

	EXPECT_TRUE(socket1.is_socket_success());
	EXPECT_TRUE(socket2.is_socket_success());
	EXPECT_TRUE(socket3.is_socket_success());
	EXPECT_TRUE(socket4.is_socket_success());
}

TEST(SocketUnitTest, ConstructorWithInvalidServerPort) {
	Config config;

	config.set_ip(SERVER_IP); config.set_port("-1");
	Socket socket1 = Socket(config);

	// config.set_ip(SERVER_IP); config.set_port("65536");
//	Socket socket2 = Socket(config);  // uisingned short 65536->0(ephemeral port)

	// config.set_ip(SERVER_IP); config.set_port("");
	// Socket socket3 = Socket(config);	// strtol->0 (tmp)

	config.set_ip(SERVER_IP); config.set_port("hoge");
	Socket socket4 = Socket(config);

	config.set_ip(SERVER_IP); config.set_port("--123123");
	Socket socket5 = Socket(config);

	config.set_ip(SERVER_IP); config.set_port("127.1");
	Socket socket6 = Socket(config);

	EXPECT_FALSE(socket1.is_socket_success());
//	EXPECT_FALSE(socket2.is_socket_success());
	// EXPECT_FALSE(socket3.is_socket_success());
	EXPECT_FALSE(socket4.is_socket_success());
	EXPECT_FALSE(socket5.is_socket_success());
	EXPECT_FALSE(socket6.is_socket_success());
}

TEST(SocketUnitTest, Getter) {
	Config config;
	config.set_ip(""); config.set_port("");

	Socket socket = Socket(config);

	EXPECT_FALSE(socket.is_socket_success());
	EXPECT_EQ(INIT_FD, socket.get_socket_fd());
}


/* ******************************************* */
/*           Socket Integration Test           */
/* ******************************************* */
TEST(SocketIntegrationTest, ConnectToClient) {
	try {
		Config config;
		config.set_ip(SERVER_IP); config.set_port(SERVER_PORT);

		Socket server = Socket(config);
		struct sockaddr_in addr = {};
		int client_fd;

		EXPECT_TRUE(server.is_socket_success());
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
		Config config;
		config.set_ip(SERVER_IP); config.set_port(SERVER_PORT);

		Socket server = Socket(config);
		int client_fd;
		struct sockaddr_in addr = {};

		EXPECT_TRUE(server.is_socket_success());
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
