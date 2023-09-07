#ifndef VALUESET_HPP
#define VALUESET_HPP

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
		ValueSet(const std::string &value);
		~ValueSet();

		std::string get_value_set(void) const;

		void show_value();
};

#endif