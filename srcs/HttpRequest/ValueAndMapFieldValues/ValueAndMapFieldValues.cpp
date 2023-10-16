#include "ValueAndMapFieldValues.hpp"

ValueAndMapFieldValues::ValueAndMapFieldValues(const std::string &value,
											   const std::map<std::string, std::string> &value_map)
	: _value(value),
	  _value_map(value_map) {}

ValueAndMapFieldValues::ValueAndMapFieldValues(const ValueAndMapFieldValues &other) {
	*this = other;
}

ValueAndMapFieldValues& ValueAndMapFieldValues::operator=(const ValueAndMapFieldValues &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_value = rhs.get_value();
	this->_value_map = rhs.get_value_map();
	return *this;
}

ValueAndMapFieldValues::~ValueAndMapFieldValues() {}

std::string ValueAndMapFieldValues::get_value() const {
	return this->_value;
}

std::map<std::string, std::string> ValueAndMapFieldValues::get_value_map() const {
	return this->_value_map;
}
