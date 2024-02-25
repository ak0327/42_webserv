#include "Constant.hpp"
#include "Color.hpp"
#include "FileHandler.hpp"
#include "gtest/gtest.h"

TEST(TestFileHandler, InvalidArgument) {
	const char *path_1 = NULL;
	const char *extension_1 = NULL;

	FileHandler file_handler_1(path_1, extension_1);
	Result<int, std::string> result_1 = file_handler_1.result();

	EXPECT_TRUE(result_1.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_1.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_2[] = "";  		// NG
	const char extension_2[] = ""; 	// NG

	FileHandler file_handler_2(path_2, extension_2);
	Result<int, std::string> result_2 = file_handler_2.result();

	EXPECT_TRUE(result_2.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_2.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_3[] = "";  		// NG
	const char extension_3[] = ".";	// NG

	FileHandler file_handler_3(path_3, extension_3);
	Result<int, std::string> result_3 = file_handler_3.result();

	EXPECT_TRUE(result_3.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_3.get_err_value());
}


TEST(TestFileHandler, InvalidExtension) {
	const char path_1[] = "test/test_conf/ok/ok1.conf";
	const char extension_1[] = "..";  // NG

	FileHandler file_handler_1(path_1, extension_1);
	Result<int, std::string> result_1 = file_handler_1.result();

	EXPECT_TRUE(result_1.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_1.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_2[] = "test/test_conf/ok/ok1.conf";
	const char extension_2[] = "c.onf";  // NG

	FileHandler file_handler_2(path_2, extension_2);
	Result<int, std::string> result_2 = file_handler_2.result();

	EXPECT_TRUE(result_2.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_2.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_3[] = "test/test_conf/ok/ok1.conf";
	const char extension_3[] = "conf.";  // NG

	FileHandler file_handler_3(path_3, extension_3);
	Result<int, std::string> result_3 = file_handler_3.result();

	EXPECT_TRUE(result_3.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_3.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_4[] = "test/test_conf/ok/ok1.conf";
	const char extension_4[] = " ";  // NG

	FileHandler file_handler_4(path_4, extension_4);
	Result<int, std::string> result_4 = file_handler_4.result();

	EXPECT_TRUE(result_4.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_4.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_5[] = "test/test_conf/ok/ok1.conf";
	const char extension_5[] = "a b";  // NG

	FileHandler file_handler_5(path_5, extension_5);
	Result<int, std::string> result_5 = file_handler_5.result();

	EXPECT_TRUE(result_5.is_err());
	EXPECT_EQ(std::string(INVALID_ARG_ERROR_MSG), result_5.get_err_value());
}


TEST(TestFileHandler, InvalidPath) {
	const char path_1[] = "nothing/xxx";  // NG
	//                     ^^^^^^^^^^^
	FileHandler file_handler_1(path_1, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_1 = file_handler_1.result();

	EXPECT_TRUE(result_1.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_1.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_2[] = "nothing/nothing.config";  // NG
	//                     ^^^^^^^^^^^^^^^^^^^^^^
	FileHandler file_handler_2(path_2, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_2 = file_handler_2.result();

	EXPECT_TRUE(result_2.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_2.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_3[] = "test/test_conf/ng/.conf";  // NG
	//                                       ^^^^^ invalid file name
	FileHandler file_handler_3(path_3, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_3 = file_handler_3.result();

	EXPECT_TRUE(result_3.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_3.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_4[] = "test/test_conf/ng/conf";  // NG
	//                                       ^^^^^ invalid file name
	FileHandler file_handler_4(path_4, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_4 = file_handler_4.result();

	EXPECT_TRUE(result_4.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_4.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_5[] = "test/test_conf/ng/nothing.conf";  // NG
	//                                       ^^^^^^^^^^^^
	FileHandler file_handler_5(path_5, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_5 = file_handler_5.result();

	EXPECT_TRUE(result_5.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_5.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_6[] = "      ";  // NG
	//                     ^^^^^^
	FileHandler file_handler_6(path_6, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_6 = file_handler_6.result();

	EXPECT_TRUE(result_6.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_6.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_7[] = "test/test_conf/ng/conf";  // NG
	//                                       ^^^^^ invalid file name
	FileHandler file_handler_7(path_7, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_7 = file_handler_7.result();

	EXPECT_TRUE(result_7.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_7.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_8[] = "test/test_conf/ng/   .conf";  // NG
	//                                       ^^^^^^^^ invalid file name
	FileHandler file_handler_8(path_8, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_8 = file_handler_8.result();

	EXPECT_TRUE(result_8.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_8.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_9[] = "test/test_conf/ok/";  // NG
	//                                      ^
	FileHandler file_handler_9(path_9, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_9 = file_handler_9.result();

	EXPECT_TRUE(result_9.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_9.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_10[] = "test/test_conf/ok/ok1.conf ";  // NG
	//                                                ^
	FileHandler file_handler_10(path_10, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_10 = file_handler_10.result();

	EXPECT_TRUE(result_10.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_10.get_err_value());
}


TEST(TestFileHandler, FileSizeTooLarge) {
	const char path_1[] = "test/test_conf/ng/65536byte.conf";  // NG
	FileHandler file_handler_1(path_1, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_1 = file_handler_1.result();

	EXPECT_TRUE(result_1.is_err());
	EXPECT_EQ(std::string(FILE_SIZE_TOO_LARGE_ERROR_MSG), result_1.get_err_value());
}


TEST(TestFileHandler, OpenNG) {
	const char path_1[] = "test/test_conf/ng/a";  // NG
	FileHandler file_handler_1(path_1, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_1 = file_handler_1.result();

	EXPECT_TRUE(result_1.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_1.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_2[] = "test/test_conf/ng/conf";  // NG
	FileHandler file_handler_2(path_2, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_2 = file_handler_2.result();

	EXPECT_TRUE(result_2.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_2.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_3[] = "test/test_conf/ng/dir.conf";  // NG
	FileHandler file_handler_3(path_3, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_3 = file_handler_3.result();

	EXPECT_TRUE(result_3.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_3.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	// Untrackable...
	// const char path_4[] = "test/test_conf/ng/permission_-w-.conf";  // NG
	// FileHandler file_handler_4(path_4, CONFIG_FILE_EXTENSION);
	// Result<int, std::string> result_4 = file_handler_4.get_result();
	//
	// EXPECT_TRUE(result_4.is_err());
	// EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_4.get_err_value());

	////////////////////////////////////////////////////////////////////////////

	const char path_5[] = "test/test_conf/ng/a.config";  // NG
	FileHandler file_handler_5(path_5, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_5 = file_handler_5.result();

	EXPECT_TRUE(result_5.is_err());
	EXPECT_EQ(std::string(INVALID_PATH_ERROR_MSG), result_5.get_err_value());
}


TEST(TestFileHandler, Contents) {
	const char path_1[] = "test/test_conf/ok/ok1.conf";
	FileHandler file_handler_1(path_1, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_1 = file_handler_1.result();
	std::string expected_contents_1 = "events {\n"
									  "}\n"
									  "\n"
									  "http {\n"
									  "}";

	EXPECT_TRUE(result_1.is_ok());
	EXPECT_EQ(expected_contents_1, file_handler_1.get_contents());
	// std::cout << CYAN << file_handler_1.get_contents() << RESET << std::endl;

	////////////////////////////////////////////////////////////////////////////

	const char path_2[] = "test/test_conf/ok/ok2.conf";
	FileHandler file_handler_2(path_2, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_2 = file_handler_2.result();
	std::string expected_contents_2 = "events {\n"
									  "}\n"
									  "\n"
									  "http {\n"
									  "\n"
									  "}";

	EXPECT_TRUE(result_2.is_ok());
	EXPECT_EQ(expected_contents_2, file_handler_2.get_contents());

	////////////////////////////////////////////////////////////////////////////

	const char path_3[] = "test/test_conf/ok/ok3.conf";
	FileHandler file_handler_3(path_3, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_3 = file_handler_3.result();
	std::string expected_contents_3 = "events {\n"
									  "}\n"
									  "\n"
									  "http\n"
									  "{\n"
									  "\n"
									  "     }";

	EXPECT_TRUE(result_3.is_ok());
	EXPECT_EQ(expected_contents_3, file_handler_3.get_contents());

	////////////////////////////////////////////////////////////////////////////

	const char path_4[] = "test/test_conf/ok/ok4.conf";
	FileHandler file_handler_4(path_4, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_4 = file_handler_4.result();
	std::string expected_contents_4 = "events {\n"
									  "}\n"
									  "\n"
									  "http\n"
									  "{\n"
									  "\n"
									  "\n"
									  "\n"
									  "\n"
									  "}\n"
									  "\n"
									  "\n"
									  "\n"
									  "\n"
									  "";

	EXPECT_TRUE(result_4.is_ok());
	EXPECT_EQ(expected_contents_4, file_handler_4.get_contents());
	// std::cout << CYAN << file_handler_4.get_contents() << RESET << std::endl;

	////////////////////////////////////////////////////////////////////////////

	const char path_5[] = "test/test_conf/ok/ok5.CONF";
	FileHandler file_handler_5(path_5, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_5 = file_handler_5.result();
	std::string expected_contents_5 = "events {\n"
									  "}\n"
									  "\n"
									  "http{\n"
									  "}";

	EXPECT_TRUE(result_5.is_ok());
	EXPECT_EQ(expected_contents_5, file_handler_5.get_contents());
	// std::cout << CYAN << file_handler_5.get_contents() << RESET << std::endl;

	////////////////////////////////////////////////////////////////////////////

	const char path_6[] = "test/test_conf/ng/empty.conf";
	FileHandler file_handler_6(path_6, CONFIG_FILE_EXTENSION);
	Result<int, std::string> result_6 = file_handler_6.result();
	std::string expected_contents_6 = std::string(EMPTY);

	EXPECT_TRUE(result_6.is_ok());
	EXPECT_EQ(expected_contents_6, file_handler_6.get_contents());
	// std::cout << CYAN << file_handler_6.get_contents() << RESET << std::endl;
}


TEST(TestFileHandler, IsValidFileName) {
    bool result;
    std::string file_name;

    file_name = "a.txt";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_TRUE(result);

    file_name = "a.text.text";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_TRUE(result);


    // -------------------------------------------------------------------------


    file_name = "";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = ".";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = ".hoge";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = "/";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = "../";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = "..";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);

    file_name = "txt";
    result = FileHandler::is_valid_file_name(file_name);
    EXPECT_FALSE(result);
}


TEST(TestFileHandler, CreateAndDeleteFile) {
    FileHandler file1("test/unit_test/test_file_handler/create.txt");
    std::string hello = "hello";
    std::vector<unsigned char> data(hello.begin(), hello.end());

    StatusCode result = file1.create_file(data);
    EXPECT_EQ(StatusOk, result);

    result = file1.create_file(data);
    EXPECT_EQ(Conflict, result);

    result = file1.delete_file();
    EXPECT_EQ(NoContent, result);

    result = file1.delete_file();
    EXPECT_EQ(NotFound, result);

    // -------------------------------------------------------------------------

    FileHandler file2("test/unit_test/test_file_handler");

    result = file2.create_file(data);
    EXPECT_EQ(BadRequest, result);

    result = file2.delete_file();
    EXPECT_EQ(BadRequest, result);

    // -------------------------------------------------------------------------

    FileHandler file4("");
    result = file4.create_file(data);
    EXPECT_EQ(BadRequest, result);

    result = file4.delete_file();
    EXPECT_EQ(BadRequest, result);

    // -------------------------------------------------------------------------

    FileHandler file6("/");
    result = file6.create_file(data);
    EXPECT_EQ(BadRequest, result);

    result = file6.delete_file();
    EXPECT_EQ(BadRequest, result);
}
