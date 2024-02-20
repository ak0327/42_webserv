#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include "Color.hpp"
#include "Constant.hpp"
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

namespace {

const int CLOSEDIR_ERROR = -1;
const DIR* OPENDIR_ERROR = NULL;

const char CURRENT_DIR[] = ".";
const char PARENT_DIR[] = "..";
const char hidden_file_prefix = '.';

std::string get_timestamp(time_t time) {
    const std::size_t BUFSIZE = 30;
    struct tm time_info;
    char formatted_time[BUFSIZE];

    localtime_r(&time, &time_info);  // todo: can use?
    strftime(formatted_time, sizeof(formatted_time), "%d-%b-%Y %H:%M", &time_info);  // todo: can use?
    return std::string(formatted_time);
}

Result<int, int> get_file_info(const std::string &directory_path_end_with_slash,
                               std::set<file_info> *ret_directories,
                               std::set<file_info> *ret_files) {
    DIR *dirp;
    struct dirent *dirent_ptr;
    struct stat stat_buf;
    struct file_info info;
    std::string filepath;
    std::string filename;
    int stat_result;

    std::set<file_info> directories, files;

    std::string err_info;
    bool is_err = false;

    if (!ret_directories || !ret_files) {
        return Result<int, int>::err(ERR);
    }

    // opendir
    errno = 0;
    dirp = opendir(directory_path_end_with_slash.c_str());
    if (dirp == OPENDIR_ERROR) {
        err_info = create_error_info(errno, __FILE__, __LINE__);
        std::cerr << err_info << std::endl;  // todo
        return Result<int, int>::err(ERR);
    }

    // readdir
    while (true) {
        errno = 0;
        dirent_ptr = readdir(dirp);
        if (!dirent_ptr) {
            if (errno != 0) {
                err_info = create_error_info(errno, __FILE__, __LINE__);
                is_err = true;
            }
            break;
        }
        filename = dirent_ptr->d_name;
        if (filename == std::string(CURRENT_DIR)
            || filename == std::string(PARENT_DIR)
            || filename[0] == hidden_file_prefix) {
            continue;
        }

        filepath = directory_path_end_with_slash + filename;

        errno = 0;
        // std::cout << CYAN << "filepath:[" << filepath << "]" << RESET << std::endl;
        stat_result = stat(filepath.c_str(), &stat_buf);
        if (stat_result == STAT_ERROR && !(errno == EACCES || errno == ENOENT)) {  // todo: linux
            // std::cout << CYAN << "errno:" << errno << RESET << std::endl;
            err_info = create_error_info(errno, __FILE__, __LINE__);
            is_err = true;
            break;
        }
        info.name = filename;
        info.size = stat_buf.st_size;

#if defined(__linux__)
        info.last_modified_time = get_timestamp(stat_buf.st_mtime);
#else
        info.last_modified_time = get_timestamp(stat_buf.st_mtimespec.tv_sec);
#endif
        if (S_ISDIR(stat_buf.st_mode)) {
            info.name += "/";
            directories.insert(info);
        } else {
            files.insert(info);
        }
    }

    errno = 0;
    if (closedir(dirp) == CLOSEDIR_ERROR) {
        err_info = create_error_info(errno, __FILE__, __LINE__);
        is_err = true;
    }

    if (is_err) {
        std::cerr << err_info << std::endl;  // todo, return err_info...?
        return Result<int, int>::err(ERR);
    }
    *ret_directories = directories;
    *ret_files = files;
    return Result<int, int>::ok(OK);
}

Result<int, int> get_directory_listing_html(const std::string &directory_path_end_with_slash,
                                            const std::set<file_info> &directories,
                                            const std::set<file_info> &files,
                                            std::vector<unsigned char> *buf) {
    std::string PARENT_DIRECTORY_CONTENT, CURRENT_DIRECTORY_CONTENT, FILE_CONTENT;
    std::set<file_info>::const_iterator itr;
    std::string name_width = "150";
    std::string time_width = "200";
    std::string size_width = "100";

    const std::string TITLE = "<html>" CRLF
                              " <head><title>Index of "
                              + directory_path_end_with_slash  // todo: path
                              + " </title></head>" CRLF;
    const std::string HEADER = "  <body>" CRLF
                               "   <h1>Index of "
                               + directory_path_end_with_slash  // todo: path
                               + "</h1>" CRLF;
    const std::string TAIL =   "  </body>" CRLF
                               "</html>" CRLF;

    const std::string TOP_HR =  "    <pre>" CRLF;
    const std::string TAIL_HR = "    </pre>" CRLF;

    const std::string TABLE_START = "    <hr> <table>" CRLF;
    const std::string TABLE_END =   "     </table> <hr>" CRLF;

    const std::string ROW_START = "      <tr>" CRLF;
    const std::string ROW_END =   "      </tr>" CRLF;

    const std::string COL_NAME_START = "       <td align=\"left\" width=\"" + name_width + "\"> ";
    const std::string COL_TIME_START = "       <td align=\"center\" width=\"" + time_width + "\"> ";
    const std::string COL_SIZE_START = "       <td align=\"center\" width=\"" + size_width + "\"> ";
    const std::string COL_END = " </td>" CRLF;

    /* parent directory */
    PARENT_DIRECTORY_CONTENT = "";
    PARENT_DIRECTORY_CONTENT.append(ROW_START);
    PARENT_DIRECTORY_CONTENT.append(COL_NAME_START + "<a href=\"../\">../</a>" + COL_END);
    PARENT_DIRECTORY_CONTENT.append(COL_TIME_START + COL_END);
    PARENT_DIRECTORY_CONTENT.append(COL_SIZE_START + COL_END);
    PARENT_DIRECTORY_CONTENT.append(ROW_END);

    /* directory */
    CURRENT_DIRECTORY_CONTENT = "";
    for (itr = directories.begin(); itr != directories.end(); ++itr) {
        std::string file_path = directory_path_end_with_slash + itr->name;
        std::ostringstream directory_oss;
        directory_oss << ROW_START;
        directory_oss << COL_NAME_START << "<a href=\"" << itr->name << "\">" << itr->name << "</a>" << COL_END;  // todo: link
        directory_oss << COL_TIME_START << itr->last_modified_time << COL_END;
        directory_oss << COL_SIZE_START << "-" << COL_END;
        directory_oss << ROW_END;
        CURRENT_DIRECTORY_CONTENT.append(directory_oss.str());
    }

    /* file */
    FILE_CONTENT = "";
    for (itr = files.begin(); itr != files.end(); ++itr) {
        std::string file_path = directory_path_end_with_slash + itr->name;
        std::ostringstream file_oss;
        file_oss << ROW_START;
        file_oss << COL_NAME_START << "<a href=\"" << itr->name << "\">" << itr->name << "</a>" << COL_END;  // todo: link
        file_oss << COL_TIME_START << itr->last_modified_time << COL_END;
        file_oss << COL_SIZE_START << itr->size << COL_END;
        file_oss << ROW_END;
        FILE_CONTENT.append(file_oss.str());
    }


    buf->insert(buf->end(), TITLE.begin(), TITLE.end());
    buf->insert(buf->end(), HEADER.begin(), HEADER.end());

    buf->insert(buf->end(), TOP_HR.begin(), TOP_HR.end());

    buf->insert(buf->end(), TABLE_START.begin(), TABLE_START.end());
    buf->insert(buf->end(), PARENT_DIRECTORY_CONTENT.begin(), PARENT_DIRECTORY_CONTENT.end());
    buf->insert(buf->end(), CURRENT_DIRECTORY_CONTENT.begin(), CURRENT_DIRECTORY_CONTENT.end());
    buf->insert(buf->end(), FILE_CONTENT.begin(), FILE_CONTENT.end());
    buf->insert(buf->end(), TABLE_END.begin(), TABLE_END.end());

    buf->insert(buf->end(), TAIL_HR.begin(), TAIL_HR.end());

    buf->insert(buf->end(), TAIL.begin(), TAIL.end());

    return Result<int, int>::ok(OK);
}

std::string get_directory_path_end_with_slash(const std::string &directory_path) {
    std::size_t len = directory_path.length();

    if (len == 0) {
        return directory_path;
    }
    if (directory_path[len - 1] == '/') {
        return directory_path;
    }
    return directory_path + "/";
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

Result<int, int> HttpResponse::get_directory_listing(const std::string &directory_path,
                                                     std::vector<unsigned char> *buf,
                                                     int *status_code) {
    if (!buf || !status_code) {
        return Result<int, int>::err(ERR);
    }

    std::string directory_path_end_with_slash = get_directory_path_end_with_slash(directory_path);
    std::set<file_info>	directories;
    std::set<file_info>	files;

    Result<int, int> get_info_result = get_file_info(directory_path_end_with_slash,
                                                     &directories,
                                                     &files);
    if (get_info_result.is_err()) {
        *status_code = STATUS_SERVER_ERROR;
        return Result<int, int>::err(ERR);
    }

    Result<int, int> get_content_result = get_directory_listing_html(directory_path_end_with_slash,
                                                                     directories,
                                                                     files,
                                                                     buf);
    if (get_content_result.is_err()) {
        *status_code = STATUS_BAD_REQUEST;
        return Result<int, int>::err(ERR);
    }
    *status_code = STATUS_OK;
    return Result<int, int>::ok(OK);
}

bool operator<(const file_info &lhs, const file_info &rhs) {
    return lhs.name < rhs.name;
}
