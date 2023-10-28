#include "SingleFieldValue.hpp"

SingleFieldValue::SingleFieldValue(const std::string &value)
	: _value(value) {}

SingleFieldValue::SingleFieldValue(const SingleFieldValue &other)
	: _value(other.get_value()) {}


SingleFieldValue& SingleFieldValue::operator=(const SingleFieldValue &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_value = rhs.get_value();
	return *this;
}

SingleFieldValue::~SingleFieldValue(){}

std::string SingleFieldValue::get_value() const {
	return this->_value;
}
