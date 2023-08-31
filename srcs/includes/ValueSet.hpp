#ifndef VALUESET_HPP
#define VALUESET_HPP

#include <vector>
#include <string>

class ValueSet: public KeyValueMap
{
	private:
		std::string	_value;

		ValueSet();
		//ValueSet &operator=(const ValueSet &other);
	
	public:
		ValueSet(const std::string &value);
		~ValueSet();

		std::string get_value_set(void) const;
};

#endif