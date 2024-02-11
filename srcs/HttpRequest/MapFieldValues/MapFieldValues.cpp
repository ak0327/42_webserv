#include <iostream>
#include "Color.hpp"
#include "Constant.hpp"
#include "MapFieldValues.hpp"
#include "HttpMessageParser.hpp"

MapFieldValues::MapFieldValues(const std::string &value,
							   const std::map<std::string, std::string> &value_map)
	: unique_value_(value),
      value_map_(value_map) {}

MapFieldValues::MapFieldValues(const std::map<std::string, std::string> &value_map)
	: value_map_(value_map){}

MapFieldValues::MapFieldValues(const MapFieldValues &other)
	: unique_value_(other.get_unique_value()),
      value_map_(other.get_value_map()) { }

MapFieldValues& MapFieldValues::operator=(const MapFieldValues &other) {
	if (this == &other) {
		return *this;
	}
	this->unique_value_ = other.get_unique_value();
	this->value_map_ = other.get_value_map();
	return *this;
}

MapFieldValues::~MapFieldValues(){}

std::string MapFieldValues::get_unique_value(void) const {
	return this->unique_value_;
}

std::map<std::string, std::string> MapFieldValues::get_value_map(void) const {
	return this->value_map_;
}

std::string MapFieldValues::get_value_by(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->value_map_.find(map_key);
	if (itr == this->value_map_.end()) {
		return std::string(EMPTY);
	}
	return itr->second;
}

bool MapFieldValues::has_map_key(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->value_map_.find(map_key);
	return itr != this->value_map_.end();
}

bool MapFieldValues::is_key_only(const std::string &value) {
	return value.empty();
}
