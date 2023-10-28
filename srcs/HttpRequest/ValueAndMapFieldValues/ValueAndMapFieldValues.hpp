#pragma once

#include <string>
#include <map>

#include "FieldValueBase.hpp"
#include "Result.hpp"

class ValueAndMapFieldValues : public FieldValueBase {
 public:
	ValueAndMapFieldValues(const std::string &value,
						   const std::map<std::string, std::string> &value_map);
	ValueAndMapFieldValues(const ValueAndMapFieldValues &other);
	virtual ~ValueAndMapFieldValues();

	ValueAndMapFieldValues &operator=(const ValueAndMapFieldValues &rhs);

	std::string get_value() const;
	std::map<std::string, std::string> get_value_map() const;

 private:
	std::string _value;
	std::map<std::string, std::string> _value_map;
};
