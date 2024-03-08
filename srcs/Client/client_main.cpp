#include <iostream>
#include "Client.hpp"

int main() {
    try {
        Client client("127.0.0.1", "4242");

        std::string request_msg = "GET / HTTP/1.1\r\n"
                                  "Host: a\r\n"
                                  "\r\n";
        client.send_msg(request_msg);
        client.recv_msg(10);
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    return 0;
}
