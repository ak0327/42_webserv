#include "gtest/gtest.h"
#include "Config.hpp"
#include "ConfigHandlingString.hpp"

TEST(UtilsTest, IsIgnoreLine) {
	EXPECT_TRUE(IsConfigFormat::is_ignore_line(""));
	EXPECT_TRUE(IsConfigFormat::is_ignore_line("#"));
	EXPECT_TRUE(IsConfigFormat::is_ignore_line("#############"));
	EXPECT_TRUE(IsConfigFormat::is_ignore_line(" # "));
	EXPECT_TRUE(IsConfigFormat::is_ignore_line(" \t\t\t#        aaaaaaaaaaaaaa "));

	EXPECT_FALSE(IsConfigFormat::is_ignore_line("\v #"));
	EXPECT_FALSE(IsConfigFormat::is_ignore_line("a #"));
	EXPECT_FALSE(IsConfigFormat::is_ignore_line("         a ############"));
}


TEST(UtilsTest, IsBlockStart) {
	EXPECT_TRUE(IsConfigFormat::is_block_start("{"));

	EXPECT_FALSE(IsConfigFormat::is_block_start("}"));
	EXPECT_FALSE(IsConfigFormat::is_block_start("{{"));
	EXPECT_FALSE(IsConfigFormat::is_block_start(""));
	EXPECT_FALSE(IsConfigFormat::is_block_start("   "));
	EXPECT_FALSE(IsConfigFormat::is_block_start("  }"));
	EXPECT_FALSE(IsConfigFormat::is_block_start("{{{{{{"));
	EXPECT_FALSE(IsConfigFormat::is_block_start("{    {"));
}

TEST(UtilsTest, IsBlockEnd) {
	EXPECT_TRUE(IsConfigFormat::is_block_end("}"));
	EXPECT_TRUE(IsConfigFormat::is_block_end("  }"));
	EXPECT_TRUE(IsConfigFormat::is_block_end("  }                "));

	EXPECT_FALSE(IsConfigFormat::is_block_end("{"));
	EXPECT_FALSE(IsConfigFormat::is_block_end(""));
	EXPECT_FALSE(IsConfigFormat::is_block_end("   "));
	EXPECT_FALSE(IsConfigFormat::is_block_end("}}}}}"));
	EXPECT_FALSE(IsConfigFormat::is_block_end("}    }"));
}

TEST(UtilsTest, IsFieldHeader) {
	// TRUE
	size_t pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_header("aaa aaa;", &pos));
	EXPECT_EQ(pos, 3);
	pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_header("aaa a;", &pos));
	EXPECT_EQ(pos, 3);
	pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_header("a aa", &pos));
	EXPECT_EQ(pos, 2);
	pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_header("aa a a a a", &pos));
	EXPECT_EQ(pos, 3);

	// FALSE
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_header("", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_header("aaa;", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_header(" ", &pos));
}


TEST(UtilsTest, IsFieldValue) {
	// TRUE
	size_t pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_value("aaa;", &pos));
	EXPECT_EQ(pos, 3);
	pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_value("a;", &pos));
	EXPECT_EQ(pos, 1);
	pos = 0;
	EXPECT_EQ(OK, IsConfigFormat::is_field_value("aa aa;", &pos));
	EXPECT_EQ(pos, 5);

	// FALSE
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_value("aa", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_value("a a", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_value(";;", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_value("aa aa ;", &pos));
	pos = 0;
	EXPECT_NE(OK, IsConfigFormat::is_field_value("aa aa; ;", &pos));
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
