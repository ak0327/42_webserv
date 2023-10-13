#include "TwoValueSet.hpp"

TwoValueSet::TwoValueSet(const std::string &first_value,  const std::string &second_value) {
	this->_firstvalue = first_value;
	this->_secondValue = second_value;
}

TwoValueSet::TwoValueSet(const TwoValueSet &other) {
	*this = other;
}

TwoValueSet& TwoValueSet::operator=(const TwoValueSet &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_firstvalue = rhs.get_firstvalue();
	this->_secondValue = rhs.get_secondvalue();
	return *this;
}

TwoValueSet::~TwoValueSet() { }

std::string TwoValueSet::get_firstvalue(void) const {
	return this->_firstvalue;
}

std::string TwoValueSet::get_secondvalue(void) const {
	return this->_secondValue;
}
