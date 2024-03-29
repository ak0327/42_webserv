#pragma once

# include <fcntl.h>
# include <sys/stat.h>
# include <fstream>
# include <string>
# include <cerrno>
# include <vector>
# include "Constant.hpp"
# include "Result.hpp"


struct IsDir {
    bool operator()(mode_t mode) const { return S_ISDIR(mode); }
};


struct IsFile {
    bool operator()(mode_t mode) const { return S_ISREG(mode); }
};


class FileHandler {
 public:
    explicit FileHandler(const std::string &path);
	FileHandler(const char *path, const char *expected_extension);
	~FileHandler();

    bool is_err() const;
	Result<int, std::string> result() const;
	const std::string &get_contents() const;
    StatusCode delete_file();
    StatusCode create_file(const std::vector<unsigned char> &data);


    Result<bool, StatusCode> is_file();
    static Result<bool, StatusCode> is_file(const std::string &path);

    Result<bool, StatusCode> is_directory();
    static Result<bool, StatusCode> is_directory(const std::string &path);

 private:
    std::string path_;
	std::string contents_;
	Result<int, std::string> result_;

	FileHandler(const FileHandler &other);
	FileHandler &operator=(const FileHandler &rhs);

	static bool is_valid_path(const char *path,
							  const char *expected_extension);
	static Result<std::string, std::string> get_file_contents(const char *path);

    static bool can_read_file(const std::string &path);
    static bool can_read_directory(const std::string &path);

    template<typename CheckFunc>
    static Result<bool, StatusCode> is_type(const std::string &path,
                                            CheckFunc check,
                                            bool (*can_open)(const std::string&));
};

# include "FileHandler.tpp"
