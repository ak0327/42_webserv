#include "../includes/ValueArraySet.hpp"

ValueArraySet::ValueArraySet(const std::vector<std::string> &value_array)
{
	this->_value_array = value_array;
}

ValueArraySet::~ValueArraySet()
{

}

std::vector<std::string>	ValueArraySet::get_value_array(void) const
{
	return (this->_value_array);
}

void	ValueArraySet::show_value_array_set(void)
{
	std::vector<std::string>::iterator it = this->_value_array.begin();

	std::cout << "value array content is >> ";
	while (it != this->_value_array.end())
	{
		if (it + 1 != _value_array.end())
			std::cout << *it << " | ";
		else
			std::cout << *it;
		it++;
	}
}