#include "../includes/ValueWeightArraySet.hpp"

ValueWeightArraySet::ValueWeightArraySet(const std::string &value)
{
	(void)value;
}

ValueWeightArraySet::~ValueWeightArraySet()
{
	//nothing to do
}

std::map<std::string, double> ValueWeightArraySet::get_valueweight_set(void) const
{
	return (this->_valueweight_set);
}

void ValueWeightArraySet::append_valueweight_set(const std::string &value, double key)
{
	this->_valueweight_set[value] = key;
}