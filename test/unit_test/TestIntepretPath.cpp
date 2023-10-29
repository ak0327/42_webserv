#include <climits>
#include <string>
#include "../../srcs/HttpResponse/DELETE/HttpResponse/HttpResponse.hpp"
#include "gtest/gtest.h"

// void	separate_path_folda_file(const std::string &request_path, std::string *search_folda, std::string *search_file)
// {
// 	size_t	path_start_pos = 0;

// 	while (request_path[path_start_pos] != ':') // skip protocol name
// 		path_start_pos++;
// 	path_start_pos = path_start_pos + 3;
// 	while (request_path[path_start_pos] != '/') // skip nankaの部分　名前なんだ
// 		path_start_pos++;
// 	std::string	path = request_path.substr(path_start_pos, request_path.length() - path_start_pos);
// 	if (path[path.length() - 1] == '/')
// 	{
// 		*search_folda = path;
// 		*search_file = "";
// 	}
// 	else
// 	{
// 		size_t	last_slash_pos = path.rfind('/');
// 		*search_folda = path.substr(0, last_slash_pos + 1);
// 		*search_file = path.substr(last_slash_pos + 1, path.length() - last_slash_pos - 1);
// 	}
// }

TEST(Interpretpath, test1) {
	std::string	folda_name;
	std::string	file_name;
	HttpResponse test;

	test.separate_path_folda_file("http://localhost:8000/", &folda_name, &file_name);
	std::cout << "here?" << std::endl;
	std::cout << folda_name << std::endl;
	EXPECT_EQ(folda_name, "/");
	std::cout << file_name << std::endl;
	EXPECT_EQ(file_name, "");
	std::cout << "end" << std::endl;
}

TEST(Interpretpath, test2) {
	std::string	folda_name;
	std::string	file_name;
	HttpResponse test;

	std::cout << "here?" << std::endl;
	test.separate_path_folda_file("http://localhost:8000/aaa", &folda_name, &file_name);
	EXPECT_EQ(folda_name, "/");
	EXPECT_EQ(file_name, "aaa");
}

TEST(Interpretpath, test3) {
	std::string	folda_name;
	std::string	file_name;
	HttpResponse test;

	test.separate_path_folda_file("http://localhost:8000/aaa/", &folda_name, &file_name);
	EXPECT_EQ(folda_name, "/aaa/");
	EXPECT_EQ(file_name, "");
}

TEST(Interpretpath, test4) {
	std::string	folda_name;
	std::string	file_name;
	HttpResponse test;

	test.separate_path_folda_file("http://localhost:8000/aaa/bbb/index.html", &folda_name, &file_name);
	EXPECT_EQ(folda_name, "/aaa/bbb/");
	EXPECT_EQ(file_name, "index.html");
}

TEST(Interpretpath, test5) {
	std::string	folda_name;
	std::string	file_name;
	HttpResponse test;

	test.separate_path_folda_file("aaa", &folda_name, &file_name);
	EXPECT_EQ(folda_name, "");
	EXPECT_EQ(file_name, "");
}