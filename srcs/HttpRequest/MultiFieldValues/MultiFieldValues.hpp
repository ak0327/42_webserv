#pragma once

#include <iostream>
#include <string>
#include <set>

#include "FieldValueBase.hpp"

class MultiFieldValues : public FieldValueBase {
 public:
	explicit MultiFieldValues(const std::set<std::string> &values);
	MultiFieldValues(const MultiFieldValues &other);
	virtual ~MultiFieldValues();

	MultiFieldValues &operator=(const MultiFieldValues &rhs);

	std::set<std::string> get_values() const;

 private:
	std::set<std::string> _field_values;
};
