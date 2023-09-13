#include "ValueWeightArraySet.hpp"

ValueWeightArraySet::ValueWeightArraySet(){}

ValueWeightArraySet& ValueWeightArraySet::operator=(ValueWeightArraySet &other)
{
	if (this == &other)
		return (*this);
	this->_valueweight_set = other.get_valueweight_set();
	return (*this);
}

ValueWeightArraySet::ValueWeightArraySet(ValueWeightArraySet &other)
{
	this->_valueweight_set = other.get_valueweight_set();
}

ValueWeightArraySet::ValueWeightArraySet(const std::map<std::string, double> &valueweight_set)
{
	this->_valueweight_set = valueweight_set;
}

ValueWeightArraySet::~ValueWeightArraySet(){}

std::map<std::string, double> ValueWeightArraySet::get_valueweight_set(void)
{
	return (this->_valueweight_set);
}

void ValueWeightArraySet::show_value()
{
	std::cout << "value are ";
	std::map<std::string, double>::iterator it = this->_valueweight_set.begin();
	while (it != this->_valueweight_set.end())
	{
		std::cout << it->first << " " << it->second << " | ";
		it++;
	}
	std::cout << std::endl;
}
