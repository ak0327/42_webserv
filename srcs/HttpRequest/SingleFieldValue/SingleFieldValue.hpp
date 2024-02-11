#pragma once

#include <iostream>
#include <string>
#include <vector>
#include "FieldValueBase.hpp"

class SingleFieldValue: public FieldValueBase {
 public:
	explicit SingleFieldValue(const std::string &value);
	SingleFieldValue(const SingleFieldValue &other);
	~SingleFieldValue();

	SingleFieldValue &operator=(const SingleFieldValue &rhs);

	std::string get_value() const;

 private:
	std::string	value_;
};
