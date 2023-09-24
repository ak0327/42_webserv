#ifndef SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_
#define SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_

#include <iostream>
#include <string>
#include <vector>
#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class ValueSet: public BaseKeyValueMap
{
	private:
		std::string	_value;
	public:
		ValueSet();
		ValueSet(const ValueSet &other);
		ValueSet &operator=(const ValueSet &other);
		explicit ValueSet(const std::string &value);
		~ValueSet();
		std::string get_value_set(void) const;
};

#endif  // SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_
