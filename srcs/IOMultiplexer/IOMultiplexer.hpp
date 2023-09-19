#pragma once

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
	virtual Result<int, std::string> register_connect_fd(int connect_fd) = 0;
	virtual Result<int, std::string> clear_fd(int clear_fd) = 0;
};

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)

class EPollMultiplexer : public IOMultiplexer {
 public:
	explicit EPollMultiplexer(int socket_fd);
	virtual ~EPollMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_fd(int clear_fd);
 private:
	int _socket_fd;
	int _epoll_fd;
	struct epoll_event _ev;
	struct epoll_event _new_event;
};

#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

class KqueueMultiplexer : public IOMultiplexer {
 public:
	explicit KqueueMultiplexer(int socket_fd);
	virtual ~KqueueMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_fd(int clear_fd);

 private:
	int _socket_fd;
	int _kq;
	struct kevent _change_event;
	struct kevent _new_event;
};

#else

class SelectMultiplexer : public IOMultiplexer {
 public:
	explicit SelectMultiplexer(int socket_fd);
	virtual ~SelectMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
	virtual Result<int, std::string> register_connect_fd(int connect_fd);
	virtual Result<int, std::string> clear_fd(int clear_fd);

 private:
	int _socket_fd;
	std::vector<int> _connect_fds;
	// std::vector<int> _ready_fds;
	// std::vector<int> _active_fds;
	fd_set _fds;
};

#endif
