#include "SetFieldValues.hpp"

SetFieldValues::SetFieldValues(const std::set<std::string> &values) {
	this->_field_values = values;
}

SetFieldValues::SetFieldValues(const SetFieldValues &other) {
	*this = other;
}

SetFieldValues& SetFieldValues::operator=(const SetFieldValues &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_field_values = rhs.get_values();
	return *this;
}

SetFieldValues::~SetFieldValues() {}

std::set<std::string> SetFieldValues::get_values() const {
	return this->_field_values;
}
