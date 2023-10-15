#include "Constant.hpp"
#include "FieldValueMap.hpp"
#include "HttpMessageParser.hpp"

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

/*
 FIELD_NAME   = #MAP_ELEMENT
 MAP_ELEMENT  = token [ "=" ( token / quoted-string ) ]
 1#element => element *( OWS "," OWS element )
 */
Result<int, int> FieldValueMap::parse_map_element(const std::string &field_value,
												  std::size_t start_pos,
												  std::size_t *end_pos,
												  std::string *key,
												  std::string *value) {
	std::size_t pos, end, len;

	if (!end_pos || !key || !value) {
		return Result<int, int>::err(ERR);
	}
	if (field_value.empty()) {
		return Result<int, int>::err(ERR);
	}

	// key
	pos = start_pos;
	len = 0;
	while (field_value[pos + len]
		   && HttpMessageParser::is_tchar(field_value[pos + len])) {
		++len;
	}
	*key = field_value.substr(pos, len);
	pos += len;

	// =
	if (field_value[pos] == ELEMENT_SEPARATOR || field_value[pos] == '\0') {
		*value = std::string(EMPTY);
		*end_pos = pos;
		return Result<int, int>::ok(OK);
	}
	if (field_value[pos] != '=') { return Result<int, int>::err(ERR); }
	++pos;

	// value
	len = 0;
	if (std::isdigit(field_value[pos])) {
		while (field_value[pos + len] && std::isdigit(field_value[pos + len])) {
			++len;
		}
	} else if (HttpMessageParser::is_tchar(field_value[pos])) {
		while (field_value[pos + len]
			   && HttpMessageParser::is_tchar(field_value[pos + len])) {
			++len;
		}
	} else if (field_value[pos] == '"') {
		HttpMessageParser::skip_quoted_string(field_value, pos, &end);
		if (pos == end) {
			return Result<int, int>::err(ERR);
		}
		len = end - pos;
	} else {
		return Result<int, int>::err(ERR);
	}
	if (len == 0) {
		return Result<int, int>::err(ERR);
	}
	*value = field_value.substr(pos, len);

	*end_pos = pos + len;
	return Result<int, int>::ok(OK);
}

bool FieldValueMap::is_key_only(const std::string &value) {
	return value.empty();
}
