#include <algorithm>
#include <string>
#include "gtest/gtest.h"
#include "HttpRequest.hpp"

bool	same_class_test_array(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず
{
	std::map<std::string, FieldValueBase*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValueBase*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
	{
		ADD_FAILURE_AT(__FILE__, line);
		return (false);
	}
	return (true);
}

bool	is_not_exist_array(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず
{
	std::map<std::string, FieldValueBase*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValueBase*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
		return (true);
	ADD_FAILURE_AT(__FILE__, line);
	return (false);
}

void	compare_vectors_report_array(std::set<std::string> target_vector,
									 std::set<std::string> subject_vector,
									 size_t line)
{
	std::set<std::string>::iterator itr_now = target_vector.begin();
	while (itr_now != target_vector.end())
	{
		if (subject_vector.find(*itr_now) == subject_vector.end())
		{
			std::cout << *itr_now << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, line);
		}
		itr_now++;
	}
}
