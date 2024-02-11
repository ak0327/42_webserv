#include "MultiFieldValues.hpp"

MultiFieldValues::MultiFieldValues(const std::set<std::string> &values) {
	this->field_values_ = values;
}

MultiFieldValues::MultiFieldValues(const MultiFieldValues &other) {
	*this = other;
}

MultiFieldValues& MultiFieldValues::operator=(const MultiFieldValues &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->field_values_ = rhs.get_values();
	return *this;
}

MultiFieldValues::~MultiFieldValues() {}

std::set<std::string> MultiFieldValues::get_values() const {
	return this->field_values_;
}
