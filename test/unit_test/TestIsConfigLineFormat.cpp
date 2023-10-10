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

TEST(IsConfigLineTest, is_start_location_block_true) 
{
	std::string	location_path;

	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aaa {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aaa          {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("location aa {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("      location a {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("      location 		any	{	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_locationblock("    location / {", &location_path));
}

TEST(IsConfigLineTest, is_start_location_block_false)
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

TEST(IsConfigLineTest, is_location_block_format_true) 
{
	bool			test_boolean = true;
	LocationConfig	test;

	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("key val; ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("	 key val    val     val;          ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config(" key val    val     val          val;", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("	 key val    val   	 val;", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("  key val    val   	 val;    ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("  } ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("  			 } ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("key val    val     val	;          ", &test_boolean, &test));
	EXPECT_EQ(true, IsConfigFormat::ready_locationblock_config("}", &test_boolean, &test));
}

TEST(IsConfigLineTest, is_location_block_format_false) 
{
	bool			test_boolean = true;
	LocationConfig	test;

	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("keyval;", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("key			val ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("	 key ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("  key ; ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("  }; ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("  		} a aaaa aaaa ", &test_boolean, &test));
	EXPECT_EQ(false, IsConfigFormat::ready_locationblock_config("key val; ;", &test_boolean, &test));
}

TEST(IsConfigLineTest, is_start_server_block_true) 
{
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server {"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server{"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("	server {	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("server		{	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("     server{"));
	EXPECT_EQ(true, IsConfigFormat::is_start_serverblock("      server 		 {		   "));
}

TEST(IsConfigLineTest, is_start_server_block_false)
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
TEST(IsConfigLineTest, is_server_block_format_true) 
{
	bool						test_boolean = true;
	ServerConfig				test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("location aaa { ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		location aaa { ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		location aaa 	{", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		key value;", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		key value		;", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		key value			;	 ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("		key value	value  value		;	 ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("}", &test_boolean, &test, &header_maps));
	EXPECT_EQ(true, IsConfigFormat::ready_serverblock_format("			} ", &test_boolean, &test, &header_maps));
}

TEST(IsConfigLineTest, is_server_block_format_false) 
{
	bool			test_boolean = true;
	ServerConfig	test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("location aaa", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("location aaa {			{", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("keyval;", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("key			val ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("	 key ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("  key ; ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("  }; ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("  		} a aaaa aaaa ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_serverblock_format("key val; ;", &test_boolean, &test, &header_maps));
}