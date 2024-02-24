# include <fcntl.h>
# include <sys/stat.h>
# include <cerrno>
# include <iostream>
# include "Color.hpp"
# include "Constant.hpp"
# include "Result.hpp"


template<typename CheckFunc>
Result<bool, StatusCode> FileHandler::is_type(const std::string &path, CheckFunc func) {
    struct stat stat_buf = {};
    errno = 0;
    int stat_result = stat(path.c_str(), &stat_buf);
    int err_no = errno;

    if (stat_result == STAT_ERROR) {
        if (err_no == ENOENT) {
            return Result<bool, StatusCode>::err(NotFound);
        }
        return Result<bool, StatusCode>::err(Forbidden);
    }

    bool result = func(stat_buf.st_mode);
    return Result<bool, StatusCode>::ok(result);
}
