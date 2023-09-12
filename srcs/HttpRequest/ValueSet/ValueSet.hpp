#ifndef SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_
#define SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_

#include <vector>
#include <string>
#include <iostream>
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
		void show_value();
};

#endif  // SRCS_HTTPREQUEST_VALUESET_VALUESET_HPP_
