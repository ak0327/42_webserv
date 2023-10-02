#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"
#include "../srcs/Config/Config.hpp"
#include <vector>
#include <algorithm>

void	compare_size_t_values_report(size_t inputed_num, size_t expected_num)
{
	EXPECT_EQ(inputed_num, expected_num);
}

void	compare_int_values_report(int inputed_num, int expected_num)
{
	EXPECT_EQ(inputed_num, expected_num);
}

void	compare_string_values_report(std::string inputed_word, std::string expected_word)
{
	EXPECT_EQ(inputed_word, expected_word);
}

void	compare_boolean_values_report(bool inputed_boolean, bool expected_boolean)
{
	EXPECT_EQ(inputed_boolean, expected_boolean);
}

// void	compare_stringvector_report(std::vector<std::string> inputed_vector, std::vector<std::string> expected_vector, size_t line)
// {
// 	std::vector<std::string>::iterator input_vector_itr=inputed_vector.begin();
// 	while (input_vector_itr != inputed_vector.end())
// 	{
// 		if (std::find(inputed_vector.begin(), inputed_vector.end()) == inputed_vector.end())
// 			ADD_FAILURE_AT(__FILE__, line);
// 		input_vector_itr++;
// 	}
// }

TEST(ConfigReading, Test1) {
	Config config_test("config/testconfig1.conf");
}
