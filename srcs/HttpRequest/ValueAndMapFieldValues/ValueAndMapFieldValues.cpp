#include <iostream>
#include "Color.hpp"
#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "Result.hpp"
#include "ValueAndMapFieldValues.hpp"

ValueAndMapFieldValues::
ValueAndMapFieldValues(const std::string &value,
					   const std::map<std::string, std::string> &value_map)
	: _value(value),
	  _value_map(value_map) {}

ValueAndMapFieldValues::ValueAndMapFieldValues(const ValueAndMapFieldValues &other) {
	*this = other;
}

ValueAndMapFieldValues
&ValueAndMapFieldValues::operator=(const ValueAndMapFieldValues &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->_value = rhs.get_value();
	this->_value_map = rhs.get_value_map();
	return *this;
}

ValueAndMapFieldValues::~ValueAndMapFieldValues() {}

std::string ValueAndMapFieldValues::get_value() const {
	return this->_value;
}

std::map<std::string, std::string> ValueAndMapFieldValues::get_value_map() const {
	return this->_value_map;
}

/*
 field-name: field_value
 field_value = VALUE *( ";" MAP_VALUES )
*/
Result<int, int>
ValueAndMapFieldValues::
parse_value_and_map_values(const std::string &field_value,
						   std::size_t start_pos,
						   std::size_t *end_pos,
						   std::string *value,
						   std::map<std::string, std::string> *map_values,
						   Result<std::string, int> (*parse_value_func)(const std::string &,
								   										std::size_t,
																	    std::size_t *),
						   Result<std::map<std::string, std::string>, int> (*parse_map_values)(const std::string &,
																							   std::size_t,
																							   std::size_t *)) {
	Result<std::string, int> value_result;
	Result<std::map<std::string, std::string>, int> map_values_result;
	std::size_t pos, end;


	if (!end_pos || !value || !map_values || !parse_value_func || !parse_map_values) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	if (field_value.empty() || field_value.length() <= start_pos) {
		return Result<int, int>::err(ERR);
	}
	pos = start_pos;

	value_result = parse_value_func(field_value, pos, &end);
	if (value_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*value = value_result.get_ok_value();

	pos = end;
	*end_pos = pos;

	if (field_value[pos] != ';') {
		return Result<int, int>::ok(OK);
	}
	// if (field_value[pos] == '\0') {
	// 	return Result<int, int>::ok(OK);
	// }
	// if (field_value[pos] != ';') {
	// 	return Result<int, int>::err(ERR);
	// }

	map_values_result = parse_map_values(field_value, pos, &end);
	if (map_values_result.is_err()) {
		return Result<int, int>::err(ERR);
	}
	*map_values = map_values_result.get_ok_value();
	pos = end;
	*end_pos = pos;
	return Result<int, int>::ok(OK);
}
