#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "MapSetFieldValues.hpp"
#include "Result.hpp"

MapSetFieldValues::MapSetFieldValues(const std::set<std::map<std::string, std::string> > &values)
	: _map_set_values(values) {}

MapSetFieldValues::MapSetFieldValues(const MapSetFieldValues &other) {
	*this = other;
}

MapSetFieldValues &MapSetFieldValues::operator=(const MapSetFieldValues &rhs) {
	if (this != &rhs) {
		return *this;
	}
	this->_map_set_values = rhs.get_map_set_values();
	return *this;
}

MapSetFieldValues::~MapSetFieldValues() {}

std::set<std::map<std::string, std::string> > MapSetFieldValues::get_map_set_values() const {
	return this->_map_set_values;
}

Result<std::set<std::map<std::string, std::string> >, int>
MapSetFieldValues::parse_map_set_field_values(const std::string &field_value,
											  Result<std::map<std::string, std::string>, int> (*parse_func)(const std::string &,
													  														std::size_t,
																										    std::size_t *)) {
	std::set<std::map<std::string, std::string> > forwarded_set;
	std::map<std::string, std::string> forwarded_elements;
	std::size_t pos, end;
	Result<std::map<std::string, std::string>, int> parse_result;
	Result<std::size_t, int> skip_result;

	if (field_value.empty()) {
		return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
	}

	pos = 0;
	while (field_value[pos]) {
		parse_result = parse_func(field_value, pos, &end);
		if (parse_result.is_err()) {
			return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
		}
		forwarded_elements = parse_result.get_ok_value();
		pos = end;

		forwarded_set.insert(forwarded_elements);

		skip_result = HttpMessageParser::skip_ows_delimiter_ows(field_value, COMMA, pos);
		if (skip_result.is_err()) {
			return Result<std::set<std::map<std::string, std::string> >, int>::err(ERR);
		}
		pos = skip_result.get_ok_value();
	}
	return Result<std::set<std::map<std::string, std::string> >, int>::ok(forwarded_set);
}
