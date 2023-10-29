#include "gtest/gtest.h"
#include "Config.hpp"

TEST(IsConfigFormatTest, AdditionalTest) {
	Config config_test1("config/");
	EXPECT_FALSE(config_test1.get_is_config_format());

	Config config_test2("config/nothing");
	EXPECT_FALSE(config_test2.get_is_config_format());

	Config config_test3("../../../../../");
	EXPECT_FALSE(config_test3.get_is_config_format());

	Config config_test4(".");
	EXPECT_FALSE(config_test4.get_is_config_format());

	Config config_test5(" ");
	EXPECT_FALSE(config_test5.get_is_config_format());

	Config config_test6("/");
	EXPECT_FALSE(config_test6.get_is_config_format());

	Config config_test7(".conf/");
	EXPECT_FALSE(config_test7.get_is_config_format());

	Config config_test8(".conf");
	EXPECT_FALSE(config_test8.get_is_config_format());

	Config config_test9("aaa.conf");
	EXPECT_FALSE(config_test9.get_is_config_format());

	Config config_test10("");
	EXPECT_FALSE(config_test10.get_is_config_format());
}

TEST(IsConfigFormatTest, IsConfigFormatTrue)
{
	Config config_test("config/testconfig1.conf");
	Config config_test2("config/testconfig2.conf");

	EXPECT_TRUE(config_test.get_is_config_format());
	EXPECT_TRUE(config_test2.get_is_config_format());
}

TEST(IsConfigFormatTest, IsConfigFormatFalse)
{
	Config config_test_error1("error_config/errortestconfig1.conf");
	Config config_test_error2("error_config/errortestconfig2.conf");
	Config config_test_error3("error_config/errortestconfig3.conf");
	Config config_test_error4("error_config/errortestconfig4.conf");

	EXPECT_FALSE(config_test_error1.get_is_config_format());
	EXPECT_FALSE(config_test_error2.get_is_config_format());
	EXPECT_FALSE(config_test_error3.get_is_config_format());
	EXPECT_FALSE(config_test_error4.get_is_config_format());
}
