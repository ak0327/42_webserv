#include <netdb.h>
#include <pthread.h>
#include <exception>
#include <string>
#include <vector>
#include <map>
#include "gtest/gtest.h"
#include "webserv.hpp"
#include "Client.hpp"
#include "Color.hpp"
#include "Configuration.hpp"
#include "Constant.hpp"
#include "Debug.hpp"
#include "Server.hpp"

namespace {

const char *SERVER_IP = "127.0.0.1";
const char *SERVER_PORT = "8080";


struct ServerTest {
	const char	*server_ip;
	const char	*server_port;
	std::string	recv_msg;
};


struct ClientTest {
	int			no;
	const char	*server_ip;
	const char	*server_port;
	std::string	send_msg;
	std::string	recv_msg;
};


/* helper */
void *run_server(void *server_info) {
    (void)server_info;
	// ServerTest *s = (ServerTest *)server_info;
	bool is_server_success = true;
    const char *file_path = "test/test_conf/test_server.conf";
    Configuration config(file_path);

	try {
		DEBUG_SERVER_PRINT("start");
		Server server = Server(config);

        ServerResult init_result = server.init();
        if (init_result.is_err()) {
            throw std::runtime_error(init_result.get_err_value());
        }
        server.set_timeout(500);
		DEBUG_SERVER_PRINT("connecting...");

        ServerResult running_result = server.run();
        if (running_result.is_err()) {
            throw std::runtime_error(running_result.get_err_value());
        }
		// s->recv_msg = server.get_recv_message();
		// vvv this func can print only 1 message vv
		// printf("server connected. recv:[%s]\n", s->recv_msg.c_str());
	}
	catch (std::exception const &e) {
		is_server_success = false;
		std::cerr << e.what() << std::endl;
	}
	return (void *)(is_server_success);
}


void *run_client(void *client_info) {
	ClientTest *c = (ClientTest *)client_info;
	bool is_client_success = true;
	std::string msg = c->send_msg;

	// if (c->no != 0) {
	// 	msg += std::to_string(c->no);
	// }

	try {
		DEBUG_PRINT(YELLOW, "client no:%d start", c->no);
		usleep(10000);
		Client client = Client(c->server_ip, c->server_port);
		DEBUG_PRINT(YELLOW, "client no:%d connecting...", c->no);
		client.send_msg(msg);
        client.recv_msg();
		c->recv_msg = client.get_recv_message();
		DEBUG_PRINT(YELLOW, "client no:%d connected. recv:[%s]", c->no, c->recv_msg.c_str());
    }
	catch (std::exception const &e) {
		is_client_success = false;
		std::cerr << e.what() << std::endl;
	}
    DEBUG_PRINT(YELLOW, "client no:%d finish", c->no);
	return (void *)(is_client_success);
}


void run_server_and_client(const char *server_ip,
						   const char *server_port,
						   const std::string &client_send_msg,
						   std::string &server_recv_msg,
						   std::string &client_recv_msg) {
	ServerTest server_info = {server_ip, server_port, ""};
	ClientTest client_info = {0, server_ip, server_port, client_send_msg, ""};
	pthread_t server_tid, client_tid;
	int ret_server, ret_client;
	bool is_server_success, is_client_success;

	ret_server = pthread_create(&server_tid, NULL, run_server, (void *)&server_info);
	ret_client = pthread_create(&client_tid, NULL, run_client, (void *)&client_info);
	if (ret_server != OK || ret_client != OK) {
		throw std::runtime_error("pthread_create error");
	}

	ret_server = pthread_join(server_tid, (void **)&is_server_success);
	ret_client = pthread_join(client_tid, (void **)&is_client_success);
	if (ret_server != OK || ret_client != OK) {
		throw std::runtime_error("pthread_join error");
	}
	if (!is_server_success) {
		throw std::runtime_error("server error");
	}
	if (!is_client_success) {
		throw std::runtime_error("client error");
	}
	server_recv_msg = server_info.recv_msg;
	client_recv_msg = client_info.recv_msg;
}


std::vector<ClientTest> init_client_infos(int client_count,
										const char *server_ip,
										const char *server_port,
										const std::vector<std::string> &client_send_msg) {
	std::vector<ClientTest> client_infos(client_count, {0, server_ip, server_port, "", ""});
	for (int i = 0; i < client_count; ++i) {
		client_infos[i].no = i;
        client_infos[i].send_msg = client_send_msg[i];
	}
	return client_infos;
}


void run_server_and_multi_client(const char *server_ip,
								 const char *server_port,
								 const std::vector<std::string> &client_send_msg,
								 std::string &server_recv_msg,
								 std::vector<std::string> &client_recv_msgs,
								 int client_count) {
	ServerTest server_info = {server_ip, server_port, ""};
	std::vector<ClientTest> client_infos = init_client_infos(client_count, server_ip, server_port, client_send_msg);
	pthread_t server_tid;
	std::vector<pthread_t> client_tids(client_count);
	int ret_server, ret_client;
	bool is_server_success, is_client_success;

	ret_server = pthread_create(&server_tid, NULL, run_server, (void *)&server_info);
	if (ret_server != OK) {
		throw std::runtime_error("pthread_create error");
	}
	for (int i = 0; i < client_count; ++i) {
		ret_client = pthread_create(&client_tids[i], NULL, run_client, (void *)&client_infos[i]);
		if (ret_client != OK) {
			throw std::runtime_error("pthread_create error");
		}
	}

	ret_server = pthread_join(server_tid, (void **)&is_server_success);
	if (ret_server != OK || !is_server_success) {
		throw std::runtime_error("server error");
	}
	for (int i = 0; i < client_count; ++i) {
		ret_client = pthread_join(client_tids[i], (void **)&is_client_success);
		if (ret_client != OK || !is_client_success) {
			throw std::runtime_error("client error");
		}
	}
	server_recv_msg = server_info.recv_msg;
	for (int i = 0; i < client_count; ++i) {
		client_recv_msgs[i] = client_infos[i].recv_msg;
        // std::cout << "client[" << i << "] received:" << client_recv_msgs[i] << std::endl;
    }
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

// int port = 49152;

TEST(ServerUnitTest, Constructor) {
    const char *file_path = "test/test_conf/test_server.conf";
    Configuration config(file_path);

	EXPECT_NO_THROW((Server(config)));
}


TEST(ServerUnitTest, ConnectClientCase1) {
	std::string msg = "test request";
	std::string server_recv_msg;
	std::string client_recv_msg;

	try {
		run_server_and_client(SERVER_IP,
							  SERVER_PORT,
							  msg,
							  server_recv_msg,
							  client_recv_msg);
		// // EXPECT_EQ(msg, server_recv_msg);
		EXPECT_EQ(msg, client_recv_msg);
		DEBUG_PRINT(YELLOW, " client_send_msg:[%s]", msg.c_str());
		// std::cerr << YELLOW " server_recv_msg:[" << server_recv_msg << "]" RESET << std::endl;
		DEBUG_PRINT(YELLOW, " client_recv_msg:[%s]", client_recv_msg.c_str());
	}
	catch (std::exception const &e) {
		FAIL() << e.what() << std::endl;
	}
}


TEST(ServerUnitTest, ConnectClientCase2) {
	std::string msg = "";
	std::string server_recv_msg;
	std::string client_recv_msg;

	try {
		run_server_and_client(SERVER_IP,
							  SERVER_PORT,
							  msg,
							  server_recv_msg,
							  client_recv_msg);
		// EXPECT_EQ(msg, server_recv_msg);
		EXPECT_EQ(msg, client_recv_msg);
		DEBUG_PRINT(YELLOW, " client_send_msg:[%s]", msg.c_str());
		// std::cerr << YELLOW " server_recv_msg:[" << server_recv_msg << "]" RESET << std::endl;
		DEBUG_PRINT(YELLOW, " client_recv_msg:[%s]", client_recv_msg.c_str());
	}
	catch (std::exception const &e) {
		FAIL() << e.what() << std::endl;
	}
}


TEST(ServerUnitTest, ConnectClientCase3) {
	std::string msg = "a\n\n\nb\n\n\n\n\r\nc\td";
	std::string server_recv_msg;
	std::string client_recv_msg;

	try {
		run_server_and_client(SERVER_IP,
							  SERVER_PORT,
							  msg,
							  server_recv_msg,
							  client_recv_msg);
		// EXPECT_EQ(msg, server_recv_msg);
		EXPECT_EQ(msg, client_recv_msg);
		DEBUG_PRINT(YELLOW, " client_send_msg:[%s]", msg.c_str());
		// std::cerr << YELLOW " server_recv_msg:[" << server_recv_msg << "]" RESET << std::endl;
		DEBUG_PRINT(YELLOW, " client_recv_msg:[%s]", client_recv_msg.c_str());
	}
	catch (std::exception const &e) {
		FAIL() << e.what() << std::endl;
	}
}


TEST(ServerUnitTest, ConnectClientCase4) {
	std::string msg =
			"GET /home.html HTTP/1.1\r\n"
			"Host: developer.mozilla.org\r\n"
			"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.9; rv:50.0) Gecko/20100101 Firefox/50.0\r\n"
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
			"Accept-Language: en-US,en;q=0.5\r\n"
			"Accept-Encoding: gzip, deflate, br\r\n"
			"Referer: https://developer.mozilla.org/testpage.html\r\n"
			"Connection: keep-alive\r\n"
			"Upgrade-Insecure-Requests: 1\r\n"
			"If-Modified-Since: Mon, 18 Jul 2016 02:36:04 GMT\r\n"
			"If-None-Match: \"c561c68d0ba92bbeb8b0fff2a9199f722e3a621a\"\r\n"
			"Cache-Control: max-age=0\r\n"
			"\r\n";
	std::string server_recv_msg;
	std::string client_recv_msg;

	try {
		run_server_and_client(SERVER_IP,
							  SERVER_PORT,
							  msg,
							  server_recv_msg,
							  client_recv_msg);
		// EXPECT_EQ(msg, server_recv_msg);
		EXPECT_EQ(msg, client_recv_msg);
		DEBUG_PRINT(YELLOW, " client_send_msg:[%s]", msg.c_str());
		// std::cerr << YELLOW " server_recv_msg:[" << server_recv_msg << "]" RESET << std::endl;
		DEBUG_PRINT(YELLOW, " client_recv_msg:[%s]", client_recv_msg.c_str());
	}
	catch (std::exception const &e) {
		FAIL() << e.what() << std::endl;
	}
}


TEST(ServerUnitTest, ConnectClientErrorInvalidIP) {
	std::string msg = "400 BAD REQUEST";
	std::string server_recv_msg;
	std::string client_recv_msg;

	EXPECT_ANY_THROW(run_server_and_client("hoge",
										   SERVER_PORT,
										   msg,
										   server_recv_msg,
										   client_recv_msg));
}


TEST(ServerUnitTest, ConnectClientErrorInvalidPort) {
	std::string msg = "400 BAD REQUEST";
	std::string server_recv_msg;
	std::string client_recv_msg;

	EXPECT_ANY_THROW(run_server_and_client(SERVER_IP,
										   "-1",
										   msg,
										   server_recv_msg,
										   client_recv_msg));
}


void test_multi_client(int client_count, const std::string &base_msg, std::size_t line) {
    std::string server_recv_msg;
    std::vector<std::string> client_recv_msgs(client_count);

    std::vector<std::string> msg;
    for (int i = 0; i < client_count; ++i) {
        std::ostringstream oss;
        oss << base_msg << ": from client No." << i;
        msg.push_back(oss.str());
        DEBUG_PRINT(MAGENTA, "create send_msg[%d]: %s", i, msg[i].c_str());
    }

    try {
        for (int i = 0; i < client_count; ++i) {
            run_server_and_multi_client(SERVER_IP,
                                        SERVER_PORT,
                                        msg,
                                        server_recv_msg,
                                        client_recv_msgs,
                                        client_count);
            DEBUG_PRINT(YELLOW, "send_msg[%d]: %s", i, msg[i].c_str());
        }
        // // EXPECT_EQ(msg, server_recv_msg);
        // std::cerr << YELLOW " server_recv_msg:[" << server_recv_msg << "]" RESET << std::endl;
        for (int i = 0; i < client_count; ++i) {
            EXPECT_EQ(msg[i], client_recv_msgs[i]) << "  at L" << line;
            DEBUG_PRINT(YELLOW, "client_recv_msg[%d]: %s", i, client_recv_msgs[i].c_str());
        }
    }
    catch (std::exception const &e) {
        FAIL() << e.what() << "  at L" << line;
    }
}


TEST(ServerUnitTest, ConnectMultiClient) {
    test_multi_client(1, "test message", __LINE__);
    test_multi_client(2, "xxxxxxxxxxxx", __LINE__);
    test_multi_client(5, "xxxxxxxxxxxx", __LINE__);
    test_multi_client(5, "", __LINE__);
    test_multi_client(5, "a", __LINE__);
    test_multi_client(5, "\n", __LINE__);
    test_multi_client(5, "\r\n", __LINE__);
    test_multi_client(20, "a b c", __LINE__);
}


TEST(ServerUnitTest, TestMultiServer) {
    Configuration config("test/test_conf/test_multi_server.conf");
    EXPECT_NO_THROW(Server server(config));
}
