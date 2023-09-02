#ifndef VALUEARRAYSET_HPP
#define VALUEARRAYSET_HPP

#include <string>
#include <vector>
#include <iostream>

#include "BaseKeyValueMap.hpp"

class ValueArraySet: public BaseKeyValueMap
{
	private:
		std::vector<std::string> _value_array;
	
	public:
		ValueArraySet();
		ValueArraySet(const ValueArraySet &other);
		ValueArraySet(const std::vector<std::string> value_array);
		ValueArraySet &operator=(const ValueArraySet &other);
		~ValueArraySet();

		std::vector<std::string>	get_value_array(void) const;

		void						show_value_array_set(void);
};

#endif