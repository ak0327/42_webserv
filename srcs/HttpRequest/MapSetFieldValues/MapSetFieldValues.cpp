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
