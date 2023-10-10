#pragma once

# include <map>
# include <string>
# include "FieldValues.hpp"

class ValueMap: public FieldValues {
 public:
	ValueMap();
	explicit ValueMap(const std::map<std::string, std::string> &value_map);

	ValueMap(const ValueMap &other);
	ValueMap(const std::string &value,
			 const std::map<std::string, std::string> &value_map);

	~ValueMap();

	ValueMap& operator=(const ValueMap &other);

	std::string get_only_value(void) const;
	std::map<std::string, std::string> get_value_map(void) const;

	void set_value(const std::string &only_value,
				   const std::map<std::string, std::string> &value_map);
	void set_value(const std::string &only_value);
	void set_value(const std::map<std::string, std::string> &value_map);

 private:
	std::string _only_value;
	std::map<std::string, std::string> _value_map;
};
