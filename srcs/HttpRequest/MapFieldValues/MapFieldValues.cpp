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

/*
 FIELD_NAME   = #MAP_ELEMENT
 MAP_ELEMENT  = token [ "=" ( token / quoted-string ) ]
 1#element => element *( OWS "," OWS element )
 */
Result<int, int> MapFieldValues::parse_map_element(const std::string &field_value,
												   std::size_t start_pos,
												   std::size_t *end_pos,
												   std::string *key,
												   std::string *value) {
	std::size_t pos, end, len;

	if (!end_pos || !key || !value) {
		return Result<int, int>::err(ERR);
	}
	*end_pos = start_pos;
	*key = std::string(EMPTY);
	*value = std::string(EMPTY);
	if (field_value.empty() || field_value.length() < start_pos) {
		return Result<int, int>::err(ERR);
	}

	// key
	pos = start_pos;
	HttpMessageParser::skip_token(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*key = field_value.substr(pos, len);
	pos += len;

	// =
	if (field_value[pos] == ELEMENT_SEPARATOR || field_value[pos] == '\0') {
		*end_pos = pos;
		return Result<int, int>::ok(OK);
	}
	if (field_value[pos] != '=') {
		return Result<int, int>::err(ERR);
	}
	++pos;

	// value
	HttpMessageParser::skip_token_or_quoted_string(field_value, pos, &end);
	if (pos == end) {
		return Result<int, int>::err(ERR);
	}
	len = end - pos;
	*value = field_value.substr(pos, len);

	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

bool MapFieldValues::is_key_only(const std::string &value) {
	return value.empty();
}
