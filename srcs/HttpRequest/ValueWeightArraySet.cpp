#include "../includes/ValueWeightArraySet.hpp"

ValueWeightArraySet::ValueWeightArraySet()
{

}

ValueWeightArraySet::ValueWeightArraySet(const ValueWeightArraySet &other)
{
	this->_valueweight_set = other->_valueweight_set;
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

void ValueWeightArraySet::append_valueweight_set(const std::string &value)
{
	std::stringstream	ss(value);
	std::string			key;
	std::string			weight;

	std::getline(ss, key, ';');
	std::getline(ss, weight, ';');
	this->_valueweight_set[key] = HandlingString::str_to_double(weight);
}