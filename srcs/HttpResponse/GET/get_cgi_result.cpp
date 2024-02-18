// #include <dirent.h>
// #include <fcntl.h>
// #include <sys/stat.h>
// #include <cerrno>
// #include <cstdio>
// #include <cstring>
// #include <ctime>
// #include <fstream>
// #include <iostream>
// #include <map>
// #include <set>
// #include <sstream>
// #include "Color.hpp"
// #include "Error.hpp"
// #include "HttpResponse.hpp"
// #include "Result.hpp"
//
//
// Result<std::string, int> HttpResponse::get_cgi_result(const std::string &file_path) const {
// 	std::string	cgi_result;
// 	std::string	command;
// 	FILE 		*pipe;
// 	char		buf[BUFSIZ];
//
// 	command = "python " + file_path;
// 	pipe = popen(command.c_str(), "r");
//
// 	if (!pipe) {
// 		return Result<std::string, int>::err(ERR);
// 	}
//
// 	while (true) {
// 		if (!fgets(buf, BUFSIZ, pipe)) {
// 			if (feof(pipe)) {
// 				break;
// 			}
// 			pclose(pipe);
// 			return Result<std::string, int>::err(ERR);
// 		}
// 		cgi_result.append(buf);
// 	}
//
// 	pclose(pipe);
// 	return Result<std::string, int>::ok(cgi_result);
// }
