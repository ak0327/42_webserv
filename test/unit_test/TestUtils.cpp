#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include "gtest/gtest.h"
#include "Socket.hpp"
#include "Color.hpp"
#include "../../srcs/Config/ConfigHandlingString/ConfigHandlingString.hpp"
#include <string>

std::vector<std::string>	obtain_field_values(const std::string &line_with_ows) // <OWS><string><OWS><string><OWS>...の時に<string>を取る関数と名付けたいが、命名不適の可能性大
{
	size_t					start_pos = 0;
	size_t					end_pos = 0;
	std::string				trim_leading_trailing_ows = HandlingString::obtain_without_ows_value(line_with_ows);
	std::vector<std::string>	field_values;

	while (true)
	{
		start_pos = end_pos;
		while (!(HandlingString::is_ows(trim_leading_trailing_ows[end_pos])))
			end_pos++;
		field_values.push_back(trim_leading_trailing_ows.substr(start_pos, end_pos - start_pos + 1));
		if (end_pos == trim_leading_trailing_ows.length())
			return field_values;
		while (HandlingString::is_ows(trim_leading_trailing_ows[end_pos]))
		{
			end_pos++;
			if (end_pos == trim_leading_trailing_ows.length())
				return field_values;
		}
		end_pos++;
	}
	return (field_values);
}

TEST(UtilTest, OWS)
{
	std::vector<std::string>	test_1 = obtain_field_values("AND  THEN 	GOOD   ");
	std::vector<std::string>	compared_vector;

	compared_vector.push_back("AND");
	compared_vector.push_back("THEN");
	compared_vector.push_back("DOOD");
	// is_array(test_1, compared_vector, 56);
}