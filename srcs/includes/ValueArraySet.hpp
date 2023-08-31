#ifndef VALUEARRAYSET_HPP
#define VALUEARRAYSET_HPP

#include <string>
#include <vector>
#include <iostream>

class ValueArraySet: public KeyValueMap
{
	private:
		std::vector<std::string> _value_array;
		
		ValueArraySet();
		ValueArraySet(const ValueArraySet &other);
		ValueArraySet &operator=(const ValueArraySet &other);
	
	public:
		ValueArraySet(const std::vector<std::string> value_array);
		~ValueArraySet();

		std::vector<std::string>	get_value_array(void) const;

		void						show_value_array_set(void);
};

#endif