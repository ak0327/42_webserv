#pragma once

# include <deque>
# include <iostream>
# include <string>
# include <vector>
# include "Result.hpp"

# if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)
#  include <sys/epoll.h>
# elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)
#  include <sys/event.h>
#  include <sys/time.h>
# else
#  include <sys/select.h>
# endif

class IOMultiplexer {
 public:
	virtual ~IOMultiplexer() {}
	virtual Result<int, std::string> get_io_ready_fd() = 0;
    virtual Result<int, std::string> register_socket_fd(int socket_fd) = 0;
    virtual Result<int, std::string> register_connect_fd(int connect_fd) = 0;
	virtual Result<int, std::string> clear_connect_fd(int clear_fd) = 0;
};

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)

class EPollMultiplexer : public IOMultiplexer {
 public:
	EPollMultiplexer();
	virtual ~EPollMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_socket_fd(int socket_fd);
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_connect_fd(int clear_fd);
 private:
	int epoll_fd_;
	struct epoll_event ev_;
	struct epoll_event new_event_;
};

#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

class KqueueMultiplexer : public IOMultiplexer {
 public:
	KqueueMultiplexer();
	virtual ~KqueueMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_socket_fd(int socket_fd);
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_connect_fd(int clear_fd);

 private:
	int kq_;
	struct kevent change_event_;
	struct kevent new_event_;
};

#else

class SelectMultiplexer : public IOMultiplexer {
 public:
	SelectMultiplexer();
	virtual ~SelectMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_socket_fd(int socket_fd);
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_connect_fd(int clear_fd);

 private:
    std::deque<int> socket_fds_;
	std::deque<int> connect_fds_;
	fd_set fds_;
    int max_fd_;

    void init_fds();
    Result<int, int> register_fd(int fd, std::deque<int> *fd_deque);
};

#endif
