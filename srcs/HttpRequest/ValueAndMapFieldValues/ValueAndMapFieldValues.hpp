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
	ValueAndMapFieldValues &operator=(const ValueAndMapFieldValues &rhs);
	virtual ~ValueAndMapFieldValues();

	std::string get_value() const;
	std::map<std::string, std::string> get_value_map() const;

	static Result<int, int> parse_value_and_map_values(const std::string &field_value,
													   std::size_t start_pos,
													   std::size_t *end_pos,
													   std::string *value,
													   std::map<std::string, std::string> *map_values,
													   Result<std::string, int> (*parse_value_func)(const std::string &,
																								    std::size_t,
																								    std::size_t *),
													   Result<std::map<std::string, std::string>, int> (*parse_map_values)(const std::string &,
																														   std::size_t,
																														   std::size_t *));

 private:
	std::string _value;
	std::map<std::string, std::string> _value_map;
};
