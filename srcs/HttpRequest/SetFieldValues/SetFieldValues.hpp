#pragma once

#include <iostream>
#include <string>
#include <set>

#include "FieldValueBase.hpp"

class SetFieldValues : public FieldValueBase {
 public:
	explicit SetFieldValues(const std::set<std::string> &values);
	SetFieldValues(const SetFieldValues &other);
	SetFieldValues &operator=(const SetFieldValues &rhs);
	virtual ~SetFieldValues();

	std::set<std::string> get_values() const;

 private:
	std::set<std::string> _field_values;
};
