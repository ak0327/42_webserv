#include "MultiFieldValues.hpp"

MultiFieldValues::MultiFieldValues(const std::set<std::string> &values) {
	this->_field_values = values;
}

MultiFieldValues::MultiFieldValues(const MultiFieldValues &other) {
	*this = other;
}

MultiFieldValues& MultiFieldValues::operator=(const MultiFieldValues &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_field_values = rhs.get_values();
	return *this;
}

MultiFieldValues::~MultiFieldValues() {}

std::set<std::string> MultiFieldValues::get_values() const {
	return this->_field_values;
}
