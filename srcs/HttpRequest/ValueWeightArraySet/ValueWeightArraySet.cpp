#include "ValueWeightArraySet.hpp"

ValueWeightArraySet::ValueWeightArraySet():BaseKeyValueMap(){}

ValueWeightArraySet& ValueWeightArraySet::operator=(const ValueWeightArraySet &other)
{
	if (this == &other)
		return (*this);
	this->_valueweight_set = other.get_valueweight_set();
	return (*this);
}

ValueWeightArraySet::ValueWeightArraySet(const ValueWeightArraySet &other):BaseKeyValueMap(other)
{
	this->_valueweight_set = other.get_valueweight_set();
}

ValueWeightArraySet::ValueWeightArraySet(const std::map<std::string, double> &valueweight_set)
{
	this->_valueweight_set = valueweight_set;
}

ValueWeightArraySet::~ValueWeightArraySet(){}

std::map<std::string, double> ValueWeightArraySet::get_valueweight_set(void) const
{
	return (this->_valueweight_set);
}
