#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Config.hpp"
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


void expect_socket(const std::string &ip, const std::string &port, bool expect_success, int line) {
    Socket socket(ip, port);

    SocketResult result1 = socket.init();
    SocketResult result2 = socket.bind();
    SocketResult result3 = socket.listen();
    SocketResult result4 = socket.set_fd_to_nonblock();

    bool total_result = result1.is_ok() && result2.is_ok() && result3.is_ok() && result4.is_ok();
    EXPECT_EQ(expect_success, total_result) << "  at L" << line;;
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

/* ******************************************* */
/*               Socket Unit Test              */
/* ******************************************* */
TEST(SocketUnitTest, ConstructorWithArgument) {
    expect_socket(SERVER_IP, SERVER_PORT, true, __LINE__);
}

TEST(SocketUnitTest, ConstructorWithValidServerIP) {
	int port = 49152;
	expect_socket("127.0.0.1", std::to_string(port++), true, __LINE__);
	expect_socket("0.0.0.0", std::to_string(port++), true, __LINE__);
	expect_socket("000.0000.00000.000000", std::to_string(port++), true, __LINE__);
}

TEST(SocketUnitTest, ConstructorWithInvalidServerIP) {
	int port = 49152;

	expect_socket("127.0.0.0.1", std::to_string(port++), false, __LINE__);
	expect_socket("256.0.0.0", std::to_string(port++), false, __LINE__);
	expect_socket("-1", std::to_string(port++), false, __LINE__);
	expect_socket("a.0.0.0", std::to_string(port++), false, __LINE__);
	expect_socket("127:0.0.1", std::to_string(port++), false, __LINE__);
	expect_socket("127,0.0.1", std::to_string(port++), false, __LINE__);
	expect_socket("127.0.0.-1", std::to_string(port++), false, __LINE__);
	expect_socket("2147483647.2147483647.2147483647.2147483647", std::to_string(port++), false, __LINE__);
	// expect_socket("", std::to_string(port++), false, __LINE__);  todo: ok?
	expect_socket("hoge", std::to_string(port++), false, __LINE__);
	expect_socket("0001.0001.0001.0001", std::to_string(port++), false, __LINE__);
	expect_socket("255.255.255.254", std::to_string(port++), false, __LINE__);

	// config.set_ip("255.255.255.255"); config.set_port(std::to_string(port++));
	// Socket socket13("255.255.255.255", std::to_string(port++).c_str());  // Linux OK, todo:error?
}

TEST(SocketUnitTest, ConstructorWithValidServerPort) {
	expect_socket(SERVER_IP, "0", true, __LINE__);  // ephemeral port
	expect_socket(SERVER_IP, "0000", true, __LINE__);
	expect_socket(SERVER_IP, "8080", true, __LINE__);
	expect_socket(SERVER_IP, "65535", true, __LINE__);
}

TEST(SocketUnitTest, ConstructorWithInvalidServerPort) {
	expect_socket(SERVER_IP, "-1", false, __LINE__);
	// config.set_ip(SERVER_IP, false, __LINE__); config.set_port("65536", false, __LINE__);
//	expect_socket(SERVER_IP, SERVER_PORT, false, __LINE__);  // uisingned short 65536->0(ephemeral port)

	// config.set_ip(SERVER_IP, false, __LINE__); config.set_port("", false, __LINE__);
	// expect_socket(SERVER_IP, SERVER_PORT, false, __LINE__);	// strtol->0 (tmp)
	expect_socket(SERVER_IP, "hoge", false, __LINE__);
	expect_socket(SERVER_IP, "--123123", false, __LINE__);
	expect_socket(SERVER_IP, "127.1", false, __LINE__);
}

TEST(SocketUnitTest, Getter) {
	Socket socket("", "");
    SocketResult result;
    result = socket.init();
    EXPECT_FALSE(result.is_ok());

    result = socket.bind();
    EXPECT_FALSE(result.is_ok());

    result = socket.listen();
    EXPECT_FALSE(result.is_ok());

    result = socket.set_fd_to_nonblock();
    EXPECT_FALSE(result.is_ok());

	EXPECT_EQ(INIT_FD, socket.get_socket_fd());
}


/* ******************************************* */
/*           Socket Integration Test           */
/* ******************************************* */
TEST(SocketIntegrationTest, ConnectToClient) {
	try {
		Socket socket(SERVER_IP, SERVER_PORT);
        SocketResult result;
        result = socket.init();
        EXPECT_TRUE(result.is_ok());

        result = socket.bind();
        EXPECT_TRUE(result.is_ok());

        result = socket.listen();
        EXPECT_TRUE(result.is_ok());

        result = socket.set_fd_to_nonblock();
        EXPECT_TRUE(result.is_ok());

		struct sockaddr_in addr = {};
		int client_fd;

		EXPECT_NE(INIT_FD, socket.get_socket_fd());

		client_fd = ::socket(AF_INET, SOCK_STREAM, 0);
		addr = create_addr();
		EXPECT_EQ(OK, connect(client_fd, (struct sockaddr *)&addr, sizeof(addr)));

		close(client_fd);
	} catch (std::exception const &e) {
		FAIL();
	}
}

TEST(SocketIntegrationTest, ConnectOverSomaxconClient) {
	try {
		Socket socket(SERVER_IP, SERVER_PORT);
        SocketResult result;
        result = socket.init();
        EXPECT_TRUE(result.is_ok());

        result = socket.bind();
        EXPECT_TRUE(result.is_ok());

        result = socket.listen();
        EXPECT_TRUE(result.is_ok());

        result = socket.set_fd_to_nonblock();
        EXPECT_TRUE(result.is_ok());
		int client_fd;
		struct sockaddr_in addr = {};

		EXPECT_NE(INIT_FD, socket.get_socket_fd());

		/* connect under SOMAXCONN */
		std::vector<int> client_fds;
		for (int i = 0; i < SOMAXCONN; ++i) {
			client_fd = ::socket(AF_INET, SOCK_STREAM, 0);
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
