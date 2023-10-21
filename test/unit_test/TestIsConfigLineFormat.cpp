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

	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("key val; ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("	 key val    val     val;          ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value(" key val    val     val          val;", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("	 key val    val   	 val;", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  key val    val   	 val;    ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  } ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  			 } ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("key val    val     val	;          ", &test_boolean, &test, &test_fieldkey_map));
	test_fieldkey_map.clear();
	EXPECT_EQ(true, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("}", &test_boolean, &test, &test_fieldkey_map));
}

TEST(IsConfigLineTest, is_location_block_format_false) 
{
	bool						test_boolean = true;
	LocationConfig				test;
	std::vector<std::string> 	test_fieldkey_map;

	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("keyval;", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("key			val ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("	 key ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  key ; ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  }; ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("  		} a aaaa aaaa ", &test_boolean, &test, &test_fieldkey_map));
	EXPECT_EQ(false, IsConfigFormat::is_location_format_ok_input_field_key_fiield_value("key val; ;", &test_boolean, &test, &test_fieldkey_map));
}

TEST(IsConfigLineTest, is_start_server_block_true) 
{
	bool	test_bool = false;

	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("server {", &test_bool));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("	server {	", &test_bool));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("server		{	", &test_bool));
	EXPECT_EQ(true, IsConfigFormat::is_start_server_block("      server 		 {		   ", &test_bool));
}

TEST(IsConfigLineTest, is_start_server_block_false)
{
	bool	test_bool = false;

	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("s", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server {{", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("      server {	   {", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("serve {", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("{", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server aaa {", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("server{", &test_bool));
	EXPECT_EQ(false, IsConfigFormat::is_start_server_block("     server{", &test_bool));
}


//testの中身は別途テストケースを追加、ここではbooleanのみ確認する
TEST(IsConfigLineTest, is_server_block_format_true) 
{
	ServerConfig				test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("location aaa { ", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		location aaa { ", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		location aaa 	{", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		key value;", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		key value		;", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		key value			;	 ", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("		key value	value  value		;	 ", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("}", &test, &header_maps));
	header_maps.clear();
	EXPECT_EQ(true, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("			} ", &test, &header_maps));
}

TEST(IsConfigLineTest, is_server_block_format_false) 
{
	ServerConfig	test;
	std::vector<std::string>	header_maps;

	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("location aaa", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("location aaa {			{", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("keyval;", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("key			val ", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("	 key ", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("  key ; ", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("  }; ", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("  		} a aaaa aaaa ", &test, &header_maps));
	EXPECT_EQ(false, IsConfigFormat::is_server_format_ok_input_field_key_fiield_value("key val; ;", &test, &header_maps));
}