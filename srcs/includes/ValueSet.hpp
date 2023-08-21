#ifndef VALUESET_HPP
#define VALUESET_HPP

#include <vector>
#include <string>

class ValueSet
{
	private:
		std::string	_value;

		ValueSet(const ValueSet &other);
		ValueSet &operator=(const ValueSet &other);
	
	public:
		ValueSet();
		~ValueSet();

		void		set_value(const std::string &value);

		std::string get_value_set(void) const;
};

#endif