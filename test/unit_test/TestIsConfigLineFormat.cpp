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

	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("location aaa {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("location aaa          {", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("location aa {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("      location a {	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("      location 		any	{	   ", &location_path));
	EXPECT_EQ(true, IsConfigFormat::is_start_location_block("    location / {", &location_path));
}

TEST(IsConfigLineTest, is_start_location_block_false)
{
	std::string	location_path;

	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("location", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("locat", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("location{{", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("      location{	   {", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("      loca tion  {", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("aaaa", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("locationaaa{", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("      location a{	   ", &location_path));
	EXPECT_EQ(false, IsConfigFormat::is_start_location_block("      location 		any	{	   {", &location_path));
}

TEST(IsConfigLineTest, is_location_block_format_true) 
{
	bool						test_boolean = true;
	LocationConfig				test;
	std::vector<std::string>	test_fieldkey_map;

	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("key val; ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("	 key val    val     val;          ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config(" key val    val     val          val;", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("	 key val    val   	 val;", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("  key val    val   	 val;    ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("  } ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("  			 } ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("key val    val     val	;          ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_location_block_config("}", &test_boolean, &test, &test_fieldkey_map));
}

TEST(IsConfigLineTest, is_location_block_format_false) 
{
	bool						test_boolean = true;
	LocationConfig				test;
	std::vector<std::string> 	test_fieldkey_map;

	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("keyval;", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("key			val ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("	 key ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("  key ; ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("  }; ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("  		} a aaaa aaaa ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::ready_location_block_config("key val; ;", &test_boolean, &test, &test_fieldkey_map));
}

TEST(IsConfigLineTest, is_start_server_block_true) 
{
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("server {"));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("	server {	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("server		{	"));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("      server 		 {		   "));
}

TEST(IsConfigLineTest, is_start_server_block_false)
{
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("s"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block(""));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server {{"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("      server {	   {"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("serve {"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("{"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server aaa {"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server{"));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("     server{"));
}


//testの中身は別途テストケースを追加、ここではbooleanのみ確認する
TEST(IsConfigLineTest, is_server_block_format_true) 
{
	bool						test_boolean = true;
	ServerConfig				test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("location aaa { ", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		location aaa { ", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		location aaa 	{", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		key value;", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		key value		;", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		key value			;	 ", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("		key value	value  value		;	 ", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("}", &test_boolean, &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::ready_server_block_format("			} ", &test_boolean, &test, &header_maps));
}

TEST(IsConfigLineTest, is_server_block_format_false) 
{
	bool			test_boolean = true;
	ServerConfig	test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("location aaa", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("location aaa {			{", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("keyval;", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("key			val ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("	 key ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("  key ; ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("  }; ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("  		} a aaaa aaaa ", &test_boolean, &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::ready_server_block_format("key val; ;", &test_boolean, &test, &header_maps));
}