#include "gtest/gtest.h"
#include "Config.hpp"
#include "ConfigHandlingString.hpp"

TEST(UtilsTest, IsIgnoreLine) {
	EXPECT_TRUE(ConfigHandlingString::is_ignore_line(""));
	EXPECT_TRUE(ConfigHandlingString::is_ignore_line("#"));
	EXPECT_TRUE(ConfigHandlingString::is_ignore_line("#############"));
	EXPECT_TRUE(ConfigHandlingString::is_ignore_line(" # "));
	EXPECT_TRUE(ConfigHandlingString::is_ignore_line(" \t\t\t#        aaaaaaaaaaaaaa "));

	EXPECT_FALSE(ConfigHandlingString::is_ignore_line("\v #"));
	EXPECT_FALSE(ConfigHandlingString::is_ignore_line("a #"));
	EXPECT_FALSE(ConfigHandlingString::is_ignore_line("         a ############"));
}


TEST(UtilsTest, IsBlockStart) {
	EXPECT_TRUE(ConfigHandlingString::is_block_start("{"));

	EXPECT_FALSE(ConfigHandlingString::is_block_start("}"));
	EXPECT_FALSE(ConfigHandlingString::is_block_start("{{"));
	EXPECT_FALSE(ConfigHandlingString::is_block_start(""));
	EXPECT_FALSE(ConfigHandlingString::is_block_start("   "));
	EXPECT_FALSE(ConfigHandlingString::is_block_start("  }"));
	EXPECT_FALSE(ConfigHandlingString::is_block_start("{{{{{{"));
	EXPECT_FALSE(ConfigHandlingString::is_block_start("{    {"));
}

TEST(UtilsTest, IsBlockEnd) {
	EXPECT_TRUE(ConfigHandlingString::is_block_end("}"));
	EXPECT_TRUE(ConfigHandlingString::is_block_end("  }"));
	EXPECT_TRUE(ConfigHandlingString::is_block_end("  }                "));

	EXPECT_FALSE(ConfigHandlingString::is_block_end("{"));
	EXPECT_FALSE(ConfigHandlingString::is_block_end(""));
	EXPECT_FALSE(ConfigHandlingString::is_block_end("   "));
	EXPECT_FALSE(ConfigHandlingString::is_block_end("}}}}}"));
	EXPECT_FALSE(ConfigHandlingString::is_block_end("}    }"));
}

TEST(UtilsTest, IsFieldHeader) {
	// todo
}


TEST(UtilsTest, IsFieldValue) {
	// todo
}

TEST(UtilsTest, ReadyStringVectorFieldValue) {
	std::vector<std::string> actual, expected;
	std::string str;

	str = "a";
	expected = {"a"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = " a";
	expected = {"a"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = "a ";
	expected = {"a"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = " a ";
	expected = {"a"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = "a b";
	expected = {"a", "b"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = "  a  b  ";
	expected = {"a", "b"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);

	str = "a b     c              d \t e       \t";
	expected = {"a", "b", "c", "d", "e"};
	actual = ConfigHandlingString::ready_string_vector_field_value(str);
	EXPECT_EQ(expected, actual);
}
