#pragma once

# include <fstream>
# include <string>
# include "Result.hpp"

class FileHandler {
 public:
	FileHandler(const char *path, const char *expected_extension);
	~FileHandler();


	Result<int, std::string> get_result();
	std::string get_contents();

 private:
	std::string contents_;
	Result<int, std::string> result_;

	FileHandler(const FileHandler &other);
	FileHandler &operator=(const FileHandler &rhs);

	static bool is_valid_extension(const char *expected_extension);
	static bool is_valid_path(const char *path,
							  const char *expected_extension);
	static Result<std::string, std::string> get_file_contents(const char *path);
};
