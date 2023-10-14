#pragma once

#include <iostream>
#include <string>
#include <set>

#include "FieldValues.hpp"

class MultiFieldValues : public FieldValues {
 public:
	explicit MultiFieldValues(const std::set<std::string> &values);
	MultiFieldValues(const MultiFieldValues &other);
	MultiFieldValues &operator=(const MultiFieldValues &rhs);
	virtual ~MultiFieldValues();

	std::set<std::string> get_values() const;

 private:
	std::set<std::string> _field_values;
};
