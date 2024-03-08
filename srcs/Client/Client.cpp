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
#include "Error.hpp"
#include "Socket.hpp"


Client::Client(const char *server_ip, const char *server_port)
    : socket_(NULL),
      connect_fd_(INIT_FD) {

    try {
        this->socket_ = new Socket(server_ip, server_port);
        SocketResult init_result = this->socket_->init();
        if (init_result.is_err()) {
            throw std::runtime_error(init_result.err_value());
        }
        SocketResult connect_result = this->socket_->connect();
        if (connect_result.is_err()) {
            throw std::runtime_error(connect_result.err_value());
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

    // std::cout << YELLOW << "client send start" << RESET << std::endl;
    // std::cout << YELLOW << " client msg[" << send_msg << "], len: " << send_msg.size()  << RESET << std::endl;
    DEBUG_CLIENT_PRINT("client send start");
    DEBUG_CLIENT_PRINT("client msg[%s], size:[%zu]", send_msg.c_str(), send_msg.size());

    errno = 0;
    send_size = send(this->connect_fd_, send_msg.c_str(), send_msg.size(), MSG_NOSIGNAL);
    if (send_size == SEND_ERROR) {
        std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
        std::string err_str = "[Client Error] send: " + error_msg;
        throw std::runtime_error(RED + err_str + RESET);
    }
    DEBUG_CLIENT_PRINT("client send end");
}

void Client::recv_msg(std::size_t bufsize = BUFSIZ) {
    ssize_t		recv_size;
    char* buf = new char[bufsize + 1];
    std::string	recv_msg;
    std::size_t total_size = 0;

    DEBUG_CLIENT_PRINT("client recv start");
    while (true) {
        errno = 0;
        recv_size = recv(this->connect_fd_, buf, bufsize, FLAG_NONE);
        DEBUG_CLIENT_PRINT(" client recv_size:%zu", recv_size);
        if (recv_size == 0) {
        	break;
        }
        if (recv_size == RECV_ERROR) {
            std::string error_msg = CREATE_ERROR_INFO_ERRNO(errno);
            std::string err_str = "[Client Error] recv: " + error_msg;
            delete[] buf;
            throw std::runtime_error(RED + err_str + RESET);
        }
        buf[recv_size] = '\0';
        total_size += recv_size;
        DEBUG_CLIENT_PRINT(" client: recv[%s], total:%zu",
                           std::string(buf, recv_size).c_str(), total_size);

        recv_msg += buf;

        if (static_cast<std::size_t>(recv_size) < bufsize) {
            break;
        }
        sleep(1);
    }
    DEBUG_CLIENT_PRINT(" client: recv_message[%s]", recv_msg.c_str());
    this->recv_message_ = recv_msg;
    DEBUG_CLIENT_PRINT("client recv end");
    delete[] buf;
}

std::string Client::get_recv_message() const { return this->recv_message_; }
