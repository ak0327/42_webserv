#include <algorithm>
#include "Constant.hpp"
#include "HttpRequest.hpp"
#include "HttpMessageParser.hpp"

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &all_value)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(all_value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, '/');
	std::getline(ss, second_value, '/');

	return (new TwoValueSet(first_value, second_value));
}

TwoValueSet* HttpRequest::ready_TwoValueSet(const std::string &value, char delimiter)
{
	std::stringstream	ss(HttpMessageParser::obtain_withoutows_value(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, delimiter);
	std::getline(ss, second_value, delimiter);
	return (new TwoValueSet(HttpMessageParser::obtain_withoutows_value(first_value), HttpMessageParser::obtain_withoutows_value(second_value)));
}
