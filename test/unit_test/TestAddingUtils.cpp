#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"
#include "../srcs/Config/Config.hpp"
#include "../srcs/Config/ConfigHandlingString/ConfigHandlingString.hpp"
#include <vector>
#include <algorithm>

TEST(UtilsTest, is_true)
{
	EXPECT_EQ(true, ConfigHandlingString::is_blockstart_endword("{"));
}

TEST(UtilsTest, is_false)
{
	EXPECT_EQ(false, ConfigHandlingString::is_blockstart_endword("{{{{{{"));
	EXPECT_EQ(false, ConfigHandlingString::is_blockstart_endword("{    {"));
}