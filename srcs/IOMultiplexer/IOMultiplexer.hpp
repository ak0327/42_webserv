#pragma once

# include <iostream>
# include <map>
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
#  include <deque>
# endif

enum FdType {
    kReadFd,
    kWriteFd,
    kFdError
};

class IOMultiplexer {
 public:
	virtual ~IOMultiplexer() {}
	virtual Result<int, std::string> get_io_ready_fd() = 0;
    virtual Result<int, std::string> register_read_fd(int read_fd) = 0;
    virtual Result<int, std::string> register_write_fd(int write_fd) = 0;
    virtual Result<int, std::string> clear_fd(int fd) = 0;
    virtual void set_timeout(int timeout_msec) = 0;
    virtual FdType get_fd_type(int fd) = 0;
};

#if defined(__linux__) && !defined(USE_SELECT_MULTIPLEXER)

class EPollMultiplexer : public IOMultiplexer {
 public:
	EPollMultiplexer();
	virtual ~EPollMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_fd(int fd);
    virtual Result<int, std::string> clear_fd(int fd);
    virtual void set_timeout(int timeout_msec);

 private:
	int epoll_fd_;
	struct epoll_event ev_;
	struct epoll_event new_event_;
    int timeout_;

    Result<int, std::string> init_epoll();
};

#elif defined(__APPLE__) && !defined(USE_SELECT_MULTIPLEXER)

class KqueueMultiplexer : public IOMultiplexer {
 public:
	KqueueMultiplexer();
	virtual ~KqueueMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_fd(int fd);
    virtual Result<int, std::string> clear_fd(int fd);
    virtual void set_timeout(int timeout_msec);

 private:
	int kq_;
	struct kevent change_event_;
	struct kevent new_event_;
    struct timespec timeout_;

    Result<int, std::string> init_kqueue();
    Result<int, std::string> kevent_wait();
    Result<int, std::string> kevent_register();
};

#else

class SelectMultiplexer : public IOMultiplexer {
 public:
	SelectMultiplexer();
	virtual ~SelectMultiplexer();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_read_fd(int read_fd);
    virtual Result<int, std::string> register_write_fd(int write_fd);
	virtual Result<int, std::string> clear_fd(int fd);
    virtual void set_timeout(int timeout_msec);

    FdType get_fd_type(int fd);

 private:
    std::map<FdType, std::deque<int> > fds_;
	std::map<FdType, fd_set> fd_set_;

    std::deque<int> read_fds_;
    std::deque<int> write_fds_;
    fd_set read_fd_set_;
    fd_set write_fd_set_;
    int max_fd_;
    struct timeval timeout_;

    void init_fds();
    int get_max_fd() const;
    int get_ready_fd() const;
    Result<int, std::string> select_fds();
};

#endif
