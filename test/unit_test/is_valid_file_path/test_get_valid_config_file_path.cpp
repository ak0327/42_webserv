#include "gtest/gtest.h"
#include "webserv.hpp"

// TEST(Test, Test) {
// 	EXPECT_EQ("OK", "OK");
// 	EXPECT_EQ("ERR", "OK");
// 	EXPECT_EQ(1, func(1));
// 	EXPECT_EQ(2, func(2));
// 	EXPECT_EQ(3, func(3));
// }

TEST(TestGetValidConfigFilePath, SimpleTest) {
	EXPECT_EQ("test/unit_test/is_valid_file_path/files/file.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/file.conf"));
	// EXPECT_EQ("test/unit_test/is_valid_file_path/files/file.CONF", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/file.CONF"));  // not supported in Linux...?
	// EXPECT_EQ("test/unit_test/is_valid_file_path/files/file.Conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/file.Conf"));  // not supported in Linux...?
	// EXPECT_EQ("test/unit_test/is_valid_file_path/files/file.conF", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/file.conF"));  // not supported in Linux...?

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/file"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/nothing.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/nothing"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/conf"));

	EXPECT_EQ("test/unit_test/is_valid_file_path/files/a.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/a.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/ a.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/a.conf "));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/ a.conf "));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/X.conf"));

	EXPECT_EQ("test/unit_test/is_valid_file_path/files/a.b.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/a.b.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/a.conf.b"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/conf.a"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/conf.a."));

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)""));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"."));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)".."));

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir.conf"));
}

TEST(TestGetValidConfigFilePath, TestDirPermissionRWX) {
	EXPECT_EQ("test/unit_test/is_valid_file_path/files/dir/file_rrr.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_rrr.conf"));
	EXPECT_EQ("test/unit_test/is_valid_file_path/files/dir/file_rr-.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_rr-.conf"));
	EXPECT_EQ("test/unit_test/is_valid_file_path/files/dir/file_r-r.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_r-r.conf"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_-rr"));  //  git add permission denied
	EXPECT_EQ("test/unit_test/is_valid_file_path/files/dir/file_r--.conf", get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_r--.conf"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_-r-"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_--r"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_---"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/this_is_dir.conf"));

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_rrr"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_rrr"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_rr-"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_-rr"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_r-r"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_-r-"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_--r"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_---"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/file_r--"));

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/dir/this_is_dir"));

}

TEST(TestGetValidConfigFilePath, TestDirPermissionRW) {
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_rrr.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_rr-.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_r-r.conf"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_-rr.conf"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_r--.conf"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_-r-.conf"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_--r.conf"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_---.conf"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/thid_is_dir.conf"));

	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_rrr"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_rr-"));
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_r-r"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_-rr"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_r--"));
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_-r-"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_--r"));  //  git add permission denied
	// EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/file_---"));  //  git add permission denied
	EXPECT_ANY_THROW(get_valid_config_file_path((char *)"test/unit_test/is_valid_file_path/files/no_x_dir/thid_is_dir"));
}
