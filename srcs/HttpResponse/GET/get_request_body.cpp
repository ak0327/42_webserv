#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <iostream>
#include <map>
#include <sstream>
#include "Error.hpp"
#include "HttpResponse.hpp"
#include "Result.hpp"

namespace {
	const std::string PATH_ROOT = "/";
	const std::string PATH_INDEX = "index.html";
	const std::string STATIC_ROOT = "www";  // todo
	const std::string PATH_DELIMITER = "/";
	const std::string NOT_FOUND_PATH = "www/404.html";

	int READ_ERROR = -1;
	int OPEN_ERROR = -1;
	int CLOSE_ERROR = -1;

	std::string decode(const std::string &target) {
		std::string decoded;
		(void)target;

		return decoded;
	}

	// "../" -> "/"
	std::string canonicalize(const std::string &path) {
		std::string canonicalized;
		(void)path;

		return canonicalized;
	}

	std::string find_resource_path(const std::string &canonicalized_path,
								   const std::string &location) {
		// todo
		return location + PATH_DELIMITER + canonicalized_path;
	}

	// location:tmp
	// '/' -> 'index.html'
	std::string get_resource_path(const std::string &target,
								  const std::map<std::string, std::string> &locations) {
		std::map<std::string, std::string>::const_iterator itr;
		std::string decoded_path;
		std::string canonicalized_path;
		std::string resource_path;

		decoded_path = decode(target);
		canonicalized_path = canonicalize(decoded_path);
		itr = locations.find(canonicalized_path);  // todo: tmp
		if (itr == locations.end()) {
			return STATIC_ROOT + target;
		}
		resource_path = find_resource_path(canonicalized_path, itr->second);
		return resource_path;
	}

	std::string get_extension(const std::string &path) {
		size_t	ext_pos;

		ext_pos = path.find_last_of('.');
		if (ext_pos == std::string::npos) {
			return "";
		}
		return path.substr(ext_pos + 1);
	}

	bool is_support_content_type(const std::string &path,
								 const std::map<std::string, std::string> &mime_types) {
		std::string extension;
		std::map<std::string, std::string>::const_iterator itr;

		extension = get_extension(path);
		itr = mime_types.find(extension);
		return itr != mime_types.end();
	}

	Result<std::string, int> get_file_content(const std::string &path, size_t *content_length) {
		ssize_t	read_size;
		char	read_buf[BUFSIZ + 1];
		int		fd;
		std::string content;

		fd = open(path.c_str(), O_RDONLY);
		if (fd == OPEN_ERROR) {
			return Result<std::string, int>::err(404);  // todo: 404?
		}
		*content_length = 0;
		while (true) {
			read_size = read(fd, read_buf, BUFSIZ);
			if (read_size == READ_ERROR) {
				*content_length = 0;
				break;
			}
			if (read_size == 0) {
				break;
			}
			read_buf[read_size] = '\0';
			*content_length += read_size;
			content += std::string(read_buf);
		}
		errno = 0;
		if (close(fd) == CLOSE_ERROR) {
			std::string err_info = create_error_info(errno, __FILE__, __LINE__);
			std::cerr << "[Error] close: " + err_info << std::endl;
		}
		return Result<std::string, int>::ok(content);
	}

	// todo: int, double,...
	std::string to_str(size_t num) {
		std::ostringstream oss;

		oss << num;
		return oss.str();
	}

}  // namespace

int HttpResponse::get_request_body(const HttpRequest &request,
								   const Configuration &config) {
	std::string path;
	Result<std::string, int> read_file_result;
	size_t content_length;

	/* path */
	path = get_resource_path(request.get_target(), config.get_locations());

	/* read file */
	if (!is_support_content_type(path, config.get_mime_types())) {
		return 406;  // Not Acceptable
	}

	/* return status */
	read_file_result = get_file_content(path, &content_length);
	if (read_file_result.is_ok()) {
		_response_body = read_file_result.get_ok_value();
		_response_headers["Content-Length"] = to_str(content_length);
		return 200;  // OK
	}
	read_file_result = get_file_content(NOT_FOUND_PATH, &content_length);
	if (read_file_result.is_err()) {
		return 404;  // Not Found
	}
	_response_body = read_file_result.get_ok_value();
	_response_headers["Content-Length"] = to_str(content_length);
	return 404;  // Not Found
}
