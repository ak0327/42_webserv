#include "StringHandler.hpp"
#include "gtest/gtest.h"

TEST(TestStringHandler, StoiConvertOK) {
	int ret;
	size_t idx;
	std::string str;
	bool		overflow;

	str = "0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "1";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "-01";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(-1, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+2147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "+00000002147483647";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(str.length(), idx);
	EXPECT_EQ(false, overflow);

	str = "2147483648";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(9, idx);
	EXPECT_EQ(true, overflow);

	str = "21474836470";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "214748364700000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(2147483647, ret);
	EXPECT_EQ(10, idx);
	EXPECT_EQ(true, overflow);

	str = "-2147483648000000";  // OF
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(-2147483648, ret);
	EXPECT_EQ(11, idx);
	EXPECT_EQ(true, overflow);

	str = " 0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, idx);
	EXPECT_EQ(false, overflow);

}

TEST(TestStringHandler, StoiConvertNG) {
	int ret;
	size_t idx;
	std::string str;
	bool overflow;

	str = " 0 ";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(2, idx);
	EXPECT_EQ(false, overflow);

	str = "0.0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "++0";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, idx);
	EXPECT_EQ(false, overflow);

	str = "";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, idx);
	EXPECT_EQ(false, overflow);

	str = "0123a";
	ret = StringHandler::stoi(str, &idx, &overflow);
	EXPECT_EQ(123, ret);
	EXPECT_EQ(4, idx);
	EXPECT_EQ(false, overflow);

}
