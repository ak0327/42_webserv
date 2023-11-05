#include "gtest/gtest.h"
#include "Config.hpp"

/*
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
*/

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
	Config config_test_error5("error_config/errortestconfig5.conf");
	Config config_test_error6("error_config/errortestconfig6.conf");
	Config config_test_error7("error_config/errortestconfig7.conf");
	Config config_test_error8("error_config/errortestconfig8.conf");
	Config config_test_error9("error_config/errortestconfig9.conf");

	EXPECT_FALSE(config_test_error1.get_is_config_format());
	EXPECT_FALSE(config_test_error2.get_is_config_format());
	EXPECT_FALSE(config_test_error3.get_is_config_format());
	EXPECT_FALSE(config_test_error4.get_is_config_format());
	EXPECT_FALSE(config_test_error5.get_is_config_format());
	EXPECT_FALSE(config_test_error6.get_is_config_format());
	EXPECT_FALSE(config_test_error7.get_is_config_format());
	EXPECT_FALSE(config_test_error8.get_is_config_format());
	EXPECT_FALSE(config_test_error9.get_is_config_format());
}

TEST(IsConfigFormatTest, IsConfigFormatOKAdditional) {
	Config config5("config/testconfig5.conf");

	EXPECT_TRUE(config5.get_is_config_format());
}


TEST(IsConfigFormatTest, IsConfigFormatNGAdditional) {
	Config config5("error_config/testconfig5.conf");  // server_name a b ;
	Config config6("error_config/testconfig6.conf");  // index index.html index.php ;
	Config config7("error_config/testconfig7.conf");  // allow_methods POST   ;
	Config config8("error_config/testconfig8.conf");  // allow_methods POST   ;
	Config config9("error_config/testconfig9.conf");  // cgi_path test/index.php ;

	Config config10("error_config/errortestconfig10.conf");
	Config config11("error_config/errortestconfig11.conf");
	Config config12("error_config/errortestconfig12.conf");
	Config config13("error_config/errortestconfig13.conf");
	Config config14("error_config/errortestconfig14.conf");
	Config config15("error_config/errortestconfig15.conf");
	Config config16("error_config/errortestconfig16.conf");
	Config config17("error_config/errortestconfig17.conf");
	Config config18("error_config/errortestconfig18.conf");
	Config config19("error_config/errortestconfig19.conf");
	Config config20("error_config/errortestconfig20.conf");
	Config config21("error_config/errortestconfig21.conf");
	Config config22("error_config/errortestconfig22.conf");
	Config config23("error_config/errortestconfig23.conf");
	Config config24("error_config/errortestconfig24.conf");
	Config config25("error_config/errortestconfig25.conf");
	Config config26("error_config/errortestconfig26.conf");
	Config config27("error_config/errortestconfig27.conf");
	Config config28("error_config/errortestconfig28.conf");

	EXPECT_FALSE(config5.get_is_config_format());
	EXPECT_FALSE(config6.get_is_config_format());
	EXPECT_FALSE(config7.get_is_config_format());
	EXPECT_FALSE(config7.get_is_config_format());
	EXPECT_FALSE(config9.get_is_config_format());

	EXPECT_FALSE(config10.get_is_config_format());  // KO? empty
	EXPECT_FALSE(config11.get_is_config_format());
	EXPECT_FALSE(config12.get_is_config_format());
	EXPECT_FALSE(config13.get_is_config_format());
	EXPECT_FALSE(config14.get_is_config_format());
	EXPECT_FALSE(config15.get_is_config_format());  // KO?
	EXPECT_FALSE(config16.get_is_config_format());  // KO?
	EXPECT_FALSE(config17.get_is_config_format());
	EXPECT_FALSE(config18.get_is_config_format());
	EXPECT_FALSE(config19.get_is_config_format());
	EXPECT_FALSE(config20.get_is_config_format());
	EXPECT_FALSE(config21.get_is_config_format());
	EXPECT_FALSE(config22.get_is_config_format());
	EXPECT_FALSE(config23.get_is_config_format());
	EXPECT_FALSE(config24.get_is_config_format());
	EXPECT_FALSE(config25.get_is_config_format());
	EXPECT_FALSE(config26.get_is_config_format());
	EXPECT_FALSE(config27.get_is_config_format());  // KO? all comment
	EXPECT_FALSE(config28.get_is_config_format());  // KO? listen 8080 8081
}