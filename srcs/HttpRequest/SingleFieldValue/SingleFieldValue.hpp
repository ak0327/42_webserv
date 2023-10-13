#pragma once

#include <iostream>
#include <string>
#include <vector>
#include "FieldValues.hpp"

class SingleFieldValue: public FieldValues {
 public:
	explicit SingleFieldValue(const std::string &value);
	SingleFieldValue(const SingleFieldValue &other);
	~SingleFieldValue();

	SingleFieldValue &operator=(const SingleFieldValue &rhs);

	std::string get_value() const;

 private:
	std::string	_value;
};
