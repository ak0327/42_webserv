#include "../includes/ValueArraySet.hpp"

ValueArraySet::ValueArraySet()
{
	
}

ValueArraySet::~ValueArraySet()
{

}

std::vector<std::string>	ValueArraySet::get_value_array(void) const
{
	return (this->_value_array);
}

void	ValueArraySet::set_value_array(const std::vector<std::string> &value)
{
	this->_value_array = value;
}