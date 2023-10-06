#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <string>
#include <vector>
#include "gtest/gtest.h"

#include "../../srcs/Config/Config.hpp"
#include "../../srcs/Config/IsConfigFormat/IsConfigFormat.hpp"
#include "../../srcs/HandlingString/HandlingString.hpp"

TEST(IsConfigTest, is_start_location_block_true) 
{
	std::string	location_path;

	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aaa {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aaa          {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aa {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("      location a {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("      location 		any	{	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("    location / {", &location_path));
}

TEST(IsConfigTest, is_start_location_block_false)
{
	std::string	location_path;

	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("location", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("locat", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("location{{", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("      location{	   {", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("      loca tion  {", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("aaaa", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("locationaaa{", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("      location a{	   ", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_locationblock("      location 		any	{	   {", &location_path));
}

TEST(IsConfigTest, is_location_block_format_true) 
{
	bool			test_boolean = true;
	LocationConfig	test;

	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("key val; ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("	 key val    val     val;          ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format(" key val    val     val          val;", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("	 key val    val   	 val;", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("  key val    val   	 val;    ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("  } ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("  			 } ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("key val    val     val	;          ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::is_locationblock_format("}", &test_boolean, &test));
}

TEST(IsConfigTest, is_location_block_format_false) 
{
	bool			test_boolean = true;
	LocationConfig	test;

	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("keyval;", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("key			val ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("	 key ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("  key ; ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("  }; ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("  		} a aaaa aaaa ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::is_locationblock_format("key val; ;", &test_boolean, &test));
}

TEST(IsConfigTest, is_start_server_block_true) 
{
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server {"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server{"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("	server {	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server		{	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("     server{"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("      server 		 {		   "));
}

TEST(IsConfigTest, is_start_server_block_false)
{
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("s"));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock(""));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("server {{"));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("      server {	   {"));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("serve {"));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("{"));
	EXPECT_EQ(false, IsConfigFormat::is_start_serverblock("server aaa {"));
}


//testの中身は別途テストケースを追加、ここではbooleanのみ確認する
TEST(IsConfigTest, is_server_block_format_true) 
{
	bool			test_boolean = true;
	bool			test_boolean_2 = true;
	ServerConfig	test;
	std::string		locationpath;

	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("location aaa { ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		location aaa { ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		location aaa 	{", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		key value;", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		key value		;", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		key value			;	 ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("		key value	value  value		;	 ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("}", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(true, IsConfigFormat::is_serverblock_format("			} ", &test_boolean, &test_boolean_2, &test, &locationpath));
}

TEST(IsConfigTest, is_server_block_format_false) 
{
	bool			test_boolean = true;
	bool			test_boolean_2 = true;
	ServerConfig	test;
	std::string		locationpath;

	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("location aaa", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("location aaa {			{", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("keyval;", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("key			val ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("	 key ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("  key ; ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("  }; ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("  		} a aaaa aaaa ", &test_boolean, &test_boolean_2, &test, &locationpath));
	EXPECT_EQ(false, IsConfigFormat::is_serverblock_format("key val; ;", &test_boolean, &test_boolean_2, &test, &locationpath));
}