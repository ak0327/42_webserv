#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include "webserv.hpp"
#include "Color.hpp"
#include "Constant.hpp"
#include "Client.hpp"
#include "Debug.hpp"
#include "Socket.hpp"


Client::Client(const char *server_ip, const char *server_port)
    : socket_(NULL),
      connect_fd_(INIT_FD) {

    try {
        this->socket_ = new Socket(server_ip, server_port);
        SocketResult init_result = this->socket_->init();
        if (init_result.is_err()) {
            throw std::runtime_error(init_result.get_err_value());
        }
        SocketResult connect_result = this->socket_->connect();
        if (connect_result.is_err()) {
            throw std::runtime_error(connect_result.get_err_value());
        }
        this->connect_fd_ = this->socket_->get_socket_fd();
    }
    catch (const std::exception &e) {
        std::cerr << RED "[Client Error] " << e.what() << RESET << std::endl;
    }
}

Client::~Client() {
    // std::cout << "client delete socket" << RESET << std::endl;
    if (this->socket_) {
        delete this->socket_;
        this->socket_ = NULL;
    }
}


void Client::send_msg(const std::string &send_msg) const {
    ssize_t	send_size;

    std::cout << YELLOW << "client send start" << RESET << std::endl;

    std::cout << YELLOW << " client msg[" << send_msg << "], len: " << send_msg.size()  << RESET << std::endl;

    errno = 0;
    send_size = send(this->connect_fd_, send_msg.c_str(), send_msg.size(), FLAG_NONE);
    if (send_size == SEND_ERROR) {
        std::string err_str = "[Client Error] send: " + std::string(strerror(errno));
        throw std::runtime_error(RED + err_str + RESET);
    }
    std::cout << YELLOW << "client send end" << RESET << std::endl;
}

void Client::recv_msg() {
    ssize_t		recv_size;
    char		buf[BUFSIZ + 1];
    std::string	recv_msg;

    std::cout << YELLOW << "client recv start" << RESET << std::endl;
    while (true) {
        errno = 0;

        recv_size = recv(this->connect_fd_, buf, BUFSIZ, FLAG_NONE);
        std::cout << YELLOW << " client recv_size:" << recv_size << RESET << std::endl;
        // if (recv_size == 0) {
        // 	break;
        // }
        if (recv_size == RECV_ERROR) {
            std::string err_str = "[Client Error] recv: " + std::string(strerror(errno));
            throw std::runtime_error(RED + err_str + RESET);
        }
        buf[recv_size] = '\0';
        std::cout << YELLOW << " client: recv[" << std::string(buf, recv_size) << "]" << RESET << std::endl;

        recv_msg += buf;

        if (recv_size < BUFSIZ) {
            break;
        }
    }
    std::cout << YELLOW << " client: recv_message[" << recv_msg << "]" << RESET << std::endl;
    this->recv_message_ = recv_msg;

    std::cout << YELLOW << "client recv end" << RESET << std::endl;
}

std::string Client::get_recv_message() const { return this->recv_message_; }
