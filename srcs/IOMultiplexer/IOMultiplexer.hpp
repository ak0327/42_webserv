#pragma once

# include <sys/select.h>
# include <iostream>
# include <map>
# include <deque>
# include <set>
# include <string>
# include <vector>
# include "Result.hpp"

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
    virtual void set_io_timeout(int timeout_msec) = 0;
    virtual FdType get_fd_type(int fd) = 0;
};


class Select : public IOMultiplexer {
 public:
	Select();
	virtual ~Select();
	virtual Result<int, std::string> get_io_ready_fd();
    virtual Result<int, std::string> register_read_fd(int read_fd);
    virtual Result<int, std::string> register_write_fd(int write_fd);
	virtual Result<int, std::string> clear_fd(int fd);
    virtual void set_io_timeout(int timeout_msec);

    FdType get_fd_type(int fd);

 private:
    std::set<int> read_fds_;
    std::set<int> write_fds_;
    std::deque<int> queue_;
    fd_set read_fd_set_;
    fd_set write_fd_set_;
    int max_fd_;
    struct timeval timeout_;

    void init_fds();
    int get_max_fd() const;
    int get_ready_fd();
    Result<int, std::string> select_fds();
};
