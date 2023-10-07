#include "../../srcs/StringHandler/StringHandler.hpp"
#include "../../srcs/HttpRequest/ValueSet/ValueSet.hpp"
#include "../../srcs/HttpRequest/TwoValueSet/TwoValueSet.hpp"
#include "../../srcs/HttpRequest/RequestLine/RequestLine.hpp"
#include "../../srcs/HttpRequest/ValueArraySet/ValueArraySet.hpp"
#include "../../srcs/HttpRequest/ValueDateSet/ValueDateSet.hpp"
#include "../../srcs/HttpRequest/ValueMap/ValueMap.hpp"
#include "../../srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../../srcs/HttpRequest/HttpRequest/HttpRequest.hpp"
#include "../../srcs/HttpRequest/SecurityPolicy/SecurityPolicy.hpp"
#include "gtest/gtest.h"
#include "../../includes/Color.hpp"
#include "../../srcs/Error/Error.hpp"
#include "../../srcs/Debug/Debug.hpp"
#include "Result.hpp"
#include <string>
#include <algorithm>

// void	compare_inputvalue_truevalue_linkclass(std::map<std::string, std::map<std::string, std::string> > test_map_values, std::map<std::string, std::map<std::string, std::string> > true_map_values, size_t line)
// {
// 	std::map<std::string, std::map<std::string, std::string> >::iterator true_itr_now = true_map_values.begin();
// 	std::map<std::string, std::string>	checking_map;
// 	std::map<std::string, std::string>	true_map;
// 	while (true_itr_now != true_map_values.end())
// 	{
// 		if (test_map_values.find(true_itr_now->first) == test_map_values.end())
// 			ADD_FAILURE_AT(__FILE__, line);
// 		else
// 		{
// 			checking_map = test_map_values[true_itr_now->first];
// 			true_map = true_map_values[true_itr_now->first];
// 			std::map<std::string, std::string>::iterator true_map_itr_now = true_map.begin();
// 			while (true_map_itr_now != true_map.end())
// 			{
// 				if (checking_map.find(true_map_itr_now->first) == true_map.end())
// 				{
// 					std::cout << true_map_itr_now->first << " is not exist" << std::endl;
// 					ADD_FAILURE_AT(__FILE__, line);
// 				}
// 				else
// 					EXPECT_EQ(checking_map[true_map_itr_now->first], true_map[true_map_itr_now->first]);
// 				true_map_itr_now++;
// 			}
// 		}
// 		true_itr_now++;
// 	}
// }

// void	compare_vectors_report(std::vector<std::string> target_vector, std::vector<std::string> subject_vector, size_t line)
// {
// 	std::vector<std::string>::iterator itr_now = target_vector.begin();
// 	while (itr_now != target_vector.end())
// 	{
// 		if (std::find(subject_vector.begin(), subject_vector.end(), *itr_now) == subject_vector.end())
// 		{
// 			std::cout << *itr_now << " is not exist" << std::endl;
// 			ADD_FAILURE_AT(__FILE__, line);
// 		}
// 		itr_now++;
// 	}
// }

// void	compare_map_report(std::map<std::string, std::vector<std::string> > target_map, std::map<std::string, std::vector<std::string> > true_map, size_t line)
// {
// 	std::map<std::string, std::vector<std::string> >::iterator itr_now = true_map.begin();
// 	while (itr_now != true_map.end())
// 	{
// 		if (target_map.find(itr_now->first) == target_map.end())
// 			ADD_FAILURE_AT(__FILE__, line);
// 		else
// 			compare_vectors_report(target_map[itr_now->first], true_map[itr_now->first], line);
// 		itr_now++;
// 	}
// }

// void	compare_daymap_report(ValueDateSet *targetdatevalue, std::string day_name, std::string day, std::string month, std::string year, std::string hour, std::string minute, std::string second)
// {
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_day_name(), day_name);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_day(), day);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_month(), month);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_year(), year);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_hour(), hour);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_minute(), minute);
// 	EXPECT_EQ(targetdatevalue->get_valuedateset_second(), second);
// }

// //valuemap1.get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1
// void	compair_valuemapset_withfirstvalue_report(std::string only_value, std::map<std::string, std::string> target_wordmap, std::string expect_only_value, std::map<std::string, std::string> expected_wordmap, std::vector<std::string> keys)
// {
// 	EXPECT_EQ(only_value, expect_only_value);
// 	std::vector<std::string>::iterator itr_now = keys.begin();
// 	while (itr_now != keys.end())
// 	{
// 		std::map<std::string, std::string>::iterator key_is_itr = target_wordmap.begin();
// 		while (key_is_itr != target_wordmap.end())
// 		{
// 			if (key_is_itr->first == *itr_now)
// 				break;
// 			key_is_itr++;
// 		}
// 		if (key_is_itr == target_wordmap.end())
// 			ADD_FAILURE_AT(__FILE__, __LINE__);
// 		else
// 			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
// 		itr_now++;
// 	}
// }

// void	check(std::map<std::string, std::string> target_wordmap, std::map<std::string, std::string> expected_wordmap, std::vector<std::string> keys)
// {
// 	std::vector<std::string>::iterator itr_now = keys.begin();
// 	while (itr_now != keys.end())
// 	{
// 		std::map<std::string, std::string>::iterator key_is_itr = target_wordmap.begin();
// 		while (key_is_itr != target_wordmap.end())
// 		{
// 			if (key_is_itr->first == *itr_now)
// 				break;
// 			key_is_itr++;
// 		}
// 		if (key_is_itr == target_wordmap.end())
// 		{
// 			std::cout << *itr_now << " is not exist" << std::endl;
// 			ADD_FAILURE_AT(__FILE__, __LINE__);
// 		}
// 		else
// 			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
// 		itr_now++;
// 	}
// }

// void	compair_valueweightarray_report(std::map<std::string, double> target_wordmap, std::map<std::string, double> expected_wordmap, std::vector<std::string> keys)
// {
// 	std::vector<std::string>::iterator itr_now = keys.begin();
// 	while (itr_now != keys.end())
// 	{
// 		std::map<std::string, double>::iterator key_is_itr = target_wordmap.begin();
// 		while (key_is_itr != target_wordmap.end())
// 		{
// 			if (key_is_itr->first == *itr_now)
// 				break;
// 			key_is_itr++;
// 		}
// 		if (key_is_itr == target_wordmap.end())
// 			ADD_FAILURE_AT(__FILE__, __LINE__);
// 		else
// 			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
// 		itr_now++;
// 	}
// }

// void	compair_twovaluemap_report(const std::string &first_target_word, const std::string &second_target_word, const std::string &exp_1, const std::string &exp_2)
// {
// 	EXPECT_EQ(first_target_word, exp_1);
// 	EXPECT_EQ(second_target_word, exp_2);
// }

// void	compair_valueset_report(const std::string &target_word, const std::string &expected_word)
// {
// 	EXPECT_EQ(target_word, expected_word);
// }

// bool	same_class_test(int line, const char *key, HttpRequest &target)
// {
// 	std::map<std::string, BaseKeyValueMap*>keyvaluemap = target.get_request_keyvalue_map();
// 	std::map<std::string, BaseKeyValueMap*>::iterator itr_now = keyvaluemap.begin();
// 	while (itr_now != keyvaluemap.end())
// 	{
// 		if (itr_now->first == key)
// 			break;
// 		itr_now++;
// 	}
// 	if (itr_now == keyvaluemap.end())
// 	{
// 		ADD_FAILURE_AT(__FILE__, line);
// 		return (false);
// 	}
// 	return (true);
// }

// bool	keyword_doesnot_exist(int line, const char *key, HttpRequest &target)
// {
// 	(void)line;
// 	std::map<std::string, BaseKeyValueMap*>keyvaluemap = target.get_request_keyvalue_map();
// 	std::map<std::string, BaseKeyValueMap*>::iterator itr_now = keyvaluemap.begin();
// 	while (itr_now != keyvaluemap.end())
// 	{
// 		if (itr_now->first == key)
// 			break;
// 		itr_now++;
// 	}
// 	if (itr_now == keyvaluemap.end())
// 	{
// 		return (false);
// 	}
// 	ADD_FAILURE_AT(__FILE__, line);
// 	return (true);
// }

int main()
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nETag: some_etag\r\nUser-Agent: YourUserAgent\r\nAccept: text/html\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	httprequest_test1.show_requestinfs();
	system("leaks a.out");
}
