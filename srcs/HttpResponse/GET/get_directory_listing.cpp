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
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

namespace {

// mv Const.h
const int OK = 0;
const int ERR = -1;
const int STAT_ERROR = -1;
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

Result<std::string, int> get_directory_listing_html(const std::string &directory_path_end_with_slash,
													const std::set<file_info> &directories,
													const std::set<file_info> &files) {
	std::string content, parent_directory_content, directory_content, file_content;
	std::set<file_info>::const_iterator itr;

	const std::string title = "<html>" CRLF
							  " <head><title>Index of "
							  + directory_path_end_with_slash  // todo: path
							  + " </title></head>" CRLF;
	const std::string header = "  <body>" CRLF
							   "   <h1>Index of "
							   + directory_path_end_with_slash  // todo: path
							   + "</h1>" CRLF;
	const std::string tail =   "  </body>" CRLF
							 "</html>" CRLF;

	const std::string top_hr =  "    <pre>" CRLF;
	const std::string tail_hr = "    </pre>" CRLF;

	const std::string table_start = "    <hr> <table>" CRLF;
	const std::string table_end =   "     </table> <hr>" CRLF;

	const std::string row_start = "      <tr>" CRLF;
	const std::string row_end =   "      </tr>" CRLF;

	const std::string col_name_start = "       <td align=\"left\" width=\"150\"> ";
	const std::string col_time_start = "       <td align=\"center\" width=\"200\"> ";
	const std::string col_size_start = "       <td align=\"center\" width=\"100\"> ";
	const std::string col_end = " </td>" CRLF;

	/* parent directory */
	parent_directory_content = "";
	parent_directory_content.append(row_start);
	parent_directory_content.append(col_name_start + "<a href=\"../\">../</a>" + col_end);
	parent_directory_content.append(col_time_start + col_end);
	parent_directory_content.append(col_size_start + col_end);
	parent_directory_content.append(row_end);

	/* directory */
	directory_content = "";
	for (itr = directories.begin(); itr != directories.end(); ++itr) {
		std::string file_path = directory_path_end_with_slash + itr->name;
		std::ostringstream directory_oss;
		directory_oss << row_start;
		directory_oss << col_name_start << "<a href=\"" << itr->name << "\">" << itr->name << "</a>" << col_end;  // todo: link
		directory_oss << col_time_start << itr->last_modified_time << col_end;
		directory_oss << col_size_start << "-" << col_end;
		directory_oss << row_end;
		directory_content.append(directory_oss.str());
	}

	/* file */
	file_content = "";
	for (itr = files.begin(); itr != files.end(); ++itr) {
		std::string file_path = directory_path_end_with_slash + itr->name;
		std::ostringstream file_oss;
		file_oss << row_start;
		file_oss << col_name_start << "<a href=\"" << itr->name << "\">" << itr->name << "</a>" << col_end;  // todo: link
		file_oss << col_time_start << itr->last_modified_time << col_end;
		file_oss << col_size_start << itr->size << col_end;
		file_oss << row_end;
		file_content.append(file_oss.str());
	}

	content = "";
	content.append(title);
	content.append(header);

	content.append(top_hr);

	content.append(table_start);
	content.append(parent_directory_content);
	content.append(directory_content);
	content.append(file_content);
	content.append(table_end);

	content.append(tail_hr);

	content.append(tail);

	// std::cout << CYAN << "content:\n" << content << RESET << std::endl;  // todo: remove later
	return Result<std::string, int>::ok(content);
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

Result<std::string, int> HttpResponse::get_directory_listing(const std::string &directory_path) const {
	std::string					content;
	std::string					directory_path_end_with_slash;
	std::set<file_info>			directories;
	std::set<file_info>			files;
	Result<int, int>			get_info_result;
	Result<std::string, int>	get_content_result;

	directory_path_end_with_slash = get_directory_path_end_with_slash(directory_path);

	get_info_result = get_file_info(directory_path_end_with_slash,
									&directories, &files);
	if (get_info_result.is_err()) {
		return Result<std::string, int>::err(ERR);
	}

	get_content_result = get_directory_listing_html(directory_path_end_with_slash,
													directories, files);
	if (get_content_result.is_err()) {
		return Result<std::string, int>::err(ERR);
	}
	content = get_content_result.get_ok_value();
	return Result<std::string, int>::ok(content);
}

bool operator<(const file_info &lhs, const file_info &rhs) {
	return lhs.name < rhs.name;
}
