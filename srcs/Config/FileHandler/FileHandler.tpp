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

    std::cout << GREEN << "  stat 1" << RESET << std::endl;
    if (stat_result == STAT_ERROR) {
        if (err_no == ENOENT) {
            std::cout << GREEN << "  stat 2 noent -> NotFound" << RESET << std::endl;
            return Result<bool, StatusCode>::err(NotFound);
        }
        std::cout << GREEN << "  stat 3 Forbidden" << RESET << std::endl;
        return Result<bool, StatusCode>::err(Forbidden);
    }

    if (!check(stat_buf.st_mode)) {
        std::cout << GREEN << "  stat 4 check fail -> false" << RESET << std::endl;
        return Result<bool, StatusCode>::ok(false);
    }
    if (!can_open(path)) {
        std::cout << GREEN << "  stat 5 can't open -> Forbidden?" << RESET << std::endl;
        return Result<bool, StatusCode>::err(Forbidden);
    }
    std::cout << GREEN << "  stat 6 -> ok" << RESET << std::endl;
    return Result<bool, StatusCode>::ok(true);
}
