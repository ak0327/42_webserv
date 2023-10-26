#include <iostream>
#include "Color.hpp"
#include "Constant.hpp"
#include "MapFieldValues.hpp"
#include "HttpMessageParser.hpp"

MapFieldValues::MapFieldValues(const std::string &value,
							   const std::map<std::string, std::string> &value_map)
	: _only_value(value),
	  _value_map(value_map) {}

MapFieldValues::MapFieldValues(const std::map<std::string, std::string> &value_map)
	: _value_map(value_map){}

MapFieldValues::MapFieldValues(const MapFieldValues &other)
	: _only_value(other.get_only_value()),
	  _value_map(other.get_value_map()) { }

MapFieldValues& MapFieldValues::operator=(const MapFieldValues &other) {
	if (this == &other) {
		return *this;
	}
	this->_only_value = other.get_only_value();
	this->_value_map = other.get_value_map();
	return *this;
}

MapFieldValues::~MapFieldValues(){}

void MapFieldValues::set_value(const std::string &only_value,
							   const std::map<std::string, std::string> &value_map) {
	this->_only_value = only_value;
	this->_value_map = value_map;
}

void MapFieldValues::set_value(const std::string &only_value) {
	this->_only_value = only_value;
}

void MapFieldValues::set_value(const std::map<std::string, std::string> &value_map) {
	this->_value_map = value_map;
}

std::string MapFieldValues::get_only_value(void) const {
	return this->_only_value;
}

std::map<std::string, std::string> MapFieldValues::get_value_map(void) const {
	return this->_value_map;
}

std::string MapFieldValues::get_value(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->_value_map.find(map_key);
	if (itr == this->_value_map.end()) {
		return std::string(EMPTY);
	}
	return itr->second;
}

bool MapFieldValues::has_map_key(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->_value_map.find(map_key);
	return itr != this->_value_map.end();
}

bool MapFieldValues::is_key_only(const std::string &value) {
	return value.empty();
}


