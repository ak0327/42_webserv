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

TEST(IsConfigLineTest, is_location_block_format_format_true) 
{
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("key val; "));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("	 key val    val     val;          "));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format(" key val    val     val          val;"));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("	 key val    val   	 val;"));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("  key val    val   	 val;    "));
	// EXPECT_EQ(true, IsConfigFormat::is_location_block_format("  } ")); block_endとして判定
	// EXPECT_EQ(true, IsConfigFormat::is_location_block_format("  			 } "));　block_endとして判定
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("key val    val     val	;          "));
	// EXPECT_EQ(true, IsConfigFormat::is_location_block_format("}")); // block_endとして判定
}

TEST(IsConfigLineTest, is_location_block_format_format_false) 
{
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("keyval;"));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("key			val "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format(""));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("	 key "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  key ; "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  }; "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  		} a aaaa aaaa "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("key val; ;"));
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
TEST(IsConfigLineTest, is_location_block_format_true) 
{
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("		key value;"));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("		key value		;"));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("		key value			;	 "));
	EXPECT_EQ(true, IsConfigFormat::is_location_block_format("		key value	value  value		;	 "));
}

TEST(IsConfigLineTest, is_location_block_format_false) 
{
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("keyval;"));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("key			val "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format(""));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("	 key "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  key ; "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  }; "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("  		} a aaaa aaaa "));
	EXPECT_EQ(false, IsConfigFormat::is_location_block_format("key val; ;"));
}