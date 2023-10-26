#pragma once

# include <map>
# include <string>
# include "FieldValueBase.hpp"
# include "Result.hpp"

class MapFieldValues : public FieldValueBase {
 public:
	explicit MapFieldValues(const std::map<std::string, std::string> &value_map);

	MapFieldValues(const MapFieldValues &other);
	MapFieldValues(const std::string &value,
				   const std::map<std::string, std::string> &value_map);

	virtual ~MapFieldValues();

	MapFieldValues& operator=(const MapFieldValues &other);

	std::map<std::string, std::string> get_value_map() const;
	std::string get_value_by(const std::string &map_key) const;
	std::string get_unique_value(void) const;
	bool has_map_key(const std::string &map_key) const;

	////////////////////////////////////////////////////////////////////////

	static bool is_key_only(const std::string &value);

 private:
	std::string _unique_value;
	std::map<std::string, std::string> _value_map;
};
