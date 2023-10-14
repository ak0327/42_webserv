#include "Constant.hpp"
#include "FieldValueMap.hpp"

FieldValueMap::FieldValueMap(const std::string &value,
							 const std::map<std::string, std::string> &value_map)
	: _only_value(value),
	  _value_map(value_map) {}

FieldValueMap::FieldValueMap(const std::map<std::string, std::string> &value_map)
	: _value_map(value_map){}

FieldValueMap::FieldValueMap(const FieldValueMap &other)
	: _only_value(other.get_only_value()),
	  _value_map(other.get_value_map()) { }

FieldValueMap& FieldValueMap::operator=(const FieldValueMap &other) {
	if (this == &other) {
		return *this;
	}
	this->_only_value = other.get_only_value();
	this->_value_map = other.get_value_map();
	return *this;
}

FieldValueMap::~FieldValueMap(){}

void FieldValueMap::set_value(const std::string &only_value,
							  const std::map<std::string, std::string> &value_map) {
	this->_only_value = only_value;
	this->_value_map = value_map;
}

void FieldValueMap::set_value(const std::string &only_value) {
	this->_only_value = only_value;
}

void FieldValueMap::set_value(const std::map<std::string, std::string> &value_map) {
	this->_value_map = value_map;
}

std::string FieldValueMap::get_only_value(void) const {
	return this->_only_value;
}

std::map<std::string, std::string> FieldValueMap::get_value_map(void) const {
	return this->_value_map;
}

std::string FieldValueMap::get_value(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->_value_map.find(map_key);
	if (itr == this->_value_map.end()) {
		return std::string(EMPTY);
	}
	return itr->second;
}

bool FieldValueMap::has_map_key(const std::string &map_key) const {
	std::map<std::string, std::string>::const_iterator itr;

	itr = this->_value_map.find(map_key);
	return itr != this->_value_map.end();
}
