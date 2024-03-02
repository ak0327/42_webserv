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
#include "StringHandler.hpp"

namespace {

const int CLOSEDIR_ERROR = -1;
const DIR* OPENDIR_ERROR = NULL;

const char CURRENT_DIR[] = ".";
const char PARENT_DIR[] = "..";
const char HIDDEN_FILE_PREFIX = '.';


std::string get_timestamp(time_t time) {
    const std::size_t BUFSIZE = 30;
    char formatted_time[BUFSIZE];
    struct tm *time_info;

    time_info = std::localtime(&time);
    std::strftime(formatted_time, sizeof(formatted_time), "%d-%b-%Y %H:%M", time_info);
    return std::string(formatted_time);
}


ProcResult get_file_info(const std::string &directory_path_with_trailing_slash,
                         std::set<FileInfo> *ret_directories,
                         std::set<FileInfo> *ret_files) {
    DIR *dirp;
    struct dirent *dirent_ptr;
    struct stat stat_buf;
    struct FileInfo info;
    std::string filepath;
    std::string filename;
    int stat_result;

    std::set<FileInfo> directories, files;

    std::string err_info;
    bool is_err = false;

    if (!ret_directories || !ret_files) {
        return Failure;
    }

    // opendir
    errno = 0;
    dirp = opendir(directory_path_with_trailing_slash.c_str());
    if (dirp == OPENDIR_ERROR) {
        err_info = CREATE_ERROR_INFO_ERRNO(errno);
        std::cerr << err_info << std::endl;  // todo
        return Failure;
    }

    // readdir
    while (true) {
        errno = 0;
        dirent_ptr = readdir(dirp);
        if (!dirent_ptr) {
            if (errno != 0) {
                err_info = CREATE_ERROR_INFO_ERRNO(errno);
                is_err = true;
            }
            break;
        }
        filename = dirent_ptr->d_name;
        if (filename == std::string(CURRENT_DIR)
            || filename == std::string(PARENT_DIR)
            || filename[0] == HIDDEN_FILE_PREFIX) {
            continue;
        }

        filepath = directory_path_with_trailing_slash + filename;

        errno = 0;
        // std::cout << CYAN << "filepath:[" << filepath << "]" << RESET << std::endl;
        stat_result = stat(filepath.c_str(), &stat_buf);
        if (stat_result == STAT_ERROR && !(errno == EACCES || errno == ENOENT)) {  // todo: linux
            // std::cout << CYAN << "errno:" << errno << RESET << std::endl;
            err_info = CREATE_ERROR_INFO_ERRNO(errno);
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
        err_info = CREATE_ERROR_INFO_ERRNO(errno);
        is_err = true;
    }

    if (is_err) {
        std::cerr << err_info << std::endl;  // todo, return err_info...?
        return Failure;
    }
    *ret_directories = directories;
    *ret_files = files;
    return Success;
}


StatusCode get_directory_listing_html(const std::string &directory_path_with_trailing_slash,
                                      const std::set<FileInfo> &directories,
                                      const std::set<FileInfo> &files,
                                      std::vector<unsigned char> *buf) {
    if (!buf) { return InternalServerError; }

    std::string PARENT_DIRECTORY_CONTENT, CURRENT_DIRECTORY_CONTENT, FILE_CONTENT;
    std::set<FileInfo>::const_iterator itr;
    std::string name_width = "150";
    std::string time_width = "200";
    std::string size_width = "100";

    const std::string TITLE = "<html>" CRLF
                              " <head><title>Index of "
                              + directory_path_with_trailing_slash  // todo: path
                              + " </title></head>" CRLF;
    const std::string HEADER = "  <body>" CRLF
                               "   <h1>Index of "
                               + directory_path_with_trailing_slash  // todo: path
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
        std::string file_path = directory_path_with_trailing_slash + itr->name;
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
        std::string file_path = directory_path_with_trailing_slash + itr->name;
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

    return StatusOk;
}


}  // namespace


////////////////////////////////////////////////////////////////////////////////


StatusCode HttpResponse::get_directory_listing(const std::string &directory_path_with_trailing_slash,
                                               std::vector<unsigned char> *buf) {
    if (!buf) {
        return InternalServerError;
    }

    std::set<FileInfo>	directories;
    std::set<FileInfo>	files;
    if (get_file_info(directory_path_with_trailing_slash, &directories, &files) == Failure) {
        return InternalServerError;
    }

    StatusCode result = get_directory_listing_html(directory_path_with_trailing_slash, directories, files, buf);
    if (result == StatusOk) {
        add_content_header("html");
    }
    return result;
}


bool operator<(const FileInfo &lhs, const FileInfo &rhs) {
    return lhs.name < rhs.name;
}
