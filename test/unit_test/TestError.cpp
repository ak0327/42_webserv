#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"

TEST(ErrorMessageTest, Test1) {
	std::string err_str = "error message";
	std::string path = "test/";
	std::string file = "file.cpp";
	int line = 1;

	std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, path + file, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test2) {
	std::string err_str = "error message";
	std::string path = "test/";
	std::string file = "file.hpp";
	int line = 1;

	std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, path + file, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test3) {
	std::string err_str = "error message";
	std::string path = "/test/";
	std::string file = "file.cpp";
	int line = 1;

	std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, path + file, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test4) {
	std::string err_str = "error message";
	std::string path = "/";
	std::string file = "file.cpp";
	int line = 1;

	std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, path + file, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test5) {
	std::string err_str = "error message";
	std::string path = "/";
	int line = 1;

	std::string expected = err_str + " (" + path + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, path, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test6) {
	std::string err_str = "error message";
	std::string file = "file.cpp";
	int line = 1;

	std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
	std::string err_info = create_error_info(err_str, file, line);
	DEBUG_PRINT(YELLOW, err_info.c_str());
	EXPECT_EQ(expected, err_info);
}

TEST(ErrorMessageTest, Test7) {
    std::string file = "file.cpp";
    int line = 1;

    int errnumber = 1;
    std::string err_str = std::string(strerror(errnumber));
    std::string expected = err_str + " (" + file + ": L" + std::to_string(line) + ")";
    std::string err_info = create_error_info(errnumber, file, line);
    DEBUG_PRINT(YELLOW, err_info.c_str());
    EXPECT_EQ(expected, err_info);
}
