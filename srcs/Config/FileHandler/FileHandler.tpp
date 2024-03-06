# include <fcntl.h>
# include <sys/stat.h>
# include <cerrno>
# include <iostream>
# include "Color.hpp"
# include "Constant.hpp"
# include "Result.hpp"


template<typename CheckFunc>
Result<bool, StatusCode> FileHandler::is_type(const std::string &path,
                                              CheckFunc check,
                                              bool (*can_open)(const std::string&)) {
    struct stat stat_buf = {};
    errno = 0;
    int stat_result = stat(path.c_str(), &stat_buf);
    int err_no = errno;

    // std::cout << GREEN << "  stat 1" << RESET << std::endl;
    if (stat_result == STAT_ERROR) {
        if (err_no == ENOMEM || err_no == EOVERFLOW || err_no == EBADF || err_no == EINVAL) {
            return Result<bool, StatusCode>::err(InternalServerError);
        }
        if (err_no == ENAMETOOLONG) {
            return Result<bool, StatusCode>::err(URITooLong);
        }
        if (err_no == ENOENT || err_no == ENOTDIR) {
            // std::cout << GREEN << "  stat 2 noent or notdir -> NotFound" << RESET << std::endl;
            return Result<bool, StatusCode>::err(NotFound);
        }
        // if (err_no == EACCES) {
        //     std::cout << GREEN << "  stat 2 eaccess -> Forbidden" << RESET << std::endl;
        //     return Result<bool, StatusCode>::err(Forbidden);
        // }
        // std::cout << GREEN << "  stat 3 Forbidden, err_no: " << err_no << RESET << std::endl;
        return Result<bool, StatusCode>::err(Forbidden);
    }

    if (!check(stat_buf.st_mode)) {
        // std::cout << GREEN << "  stat 4 check fail -> false" << RESET << std::endl;
        return Result<bool, StatusCode>::ok(false);
    }
    if (!can_open(path)) {
        // std::cout << GREEN << "  stat 5 can't open -> Forbidden?" << RESET << std::endl;
        return Result<bool, StatusCode>::err(Forbidden);
    }
    // std::cout << GREEN << "  stat 6 -> ok" << RESET << std::endl;
    return Result<bool, StatusCode>::ok(true);
}
