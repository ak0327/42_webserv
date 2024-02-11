#include "SingleFieldValue.hpp"

SingleFieldValue::SingleFieldValue(const std::string &value)
	: value_(value) {}

SingleFieldValue::SingleFieldValue(const SingleFieldValue &other)
	: value_(other.get_value()) {}


SingleFieldValue& SingleFieldValue::operator=(const SingleFieldValue &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->value_ = rhs.get_value();
	return *this;
}

SingleFieldValue::~SingleFieldValue(){}

std::string SingleFieldValue::get_value() const {
	return this->value_;
}
