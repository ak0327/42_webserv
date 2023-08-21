#ifndef VALUEARRAYSET_HPP
#define VALUEARRAYSET_HPP

#include <string>
#include <vector>

class ValueArraySet
{
	private:
		std::vector<std::string> _value_array;
		
		ValueArraySet(const ValueArraySet &other);
		ValueArraySet &operator=(const ValueArraySet &other);
	
	public:
		ValueArraySet();
		~ValueArraySet();

		std::vector<std::string>	get_value_array(void) const;

		void						set_value_array(const std::vector<std::string> &value);
};

#endif