#include "Constant.hpp"
#include "HttpMessageParser.hpp"
#include "MapSetFieldValues.hpp"
#include "Result.hpp"

MapSetFieldValues::MapSetFieldValues(const std::set<std::map<std::string, std::string> > &values)
	: map_set_values_(values) {}

MapSetFieldValues::MapSetFieldValues(const MapSetFieldValues &other) {
	*this = other;
}

MapSetFieldValues &MapSetFieldValues::operator=(const MapSetFieldValues &rhs) {
	if (this != &rhs) {
		return *this;
	}
	this->map_set_values_ = rhs.get_map_set_values();
	return *this;
}

MapSetFieldValues::~MapSetFieldValues() {}

std::set<std::map<std::string, std::string> > MapSetFieldValues::get_map_set_values() const {
	return this->map_set_values_;
}
