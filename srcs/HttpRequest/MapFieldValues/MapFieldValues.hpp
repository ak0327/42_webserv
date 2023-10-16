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
	std::string get_value(const std::string &map_key) const;
	bool has_map_key(const std::string &map_key) const;

	////////////////////////////////////////////////////////////////////////

	std::string get_only_value(void) const;

	void set_value(const std::string &only_value,
				   const std::map<std::string, std::string> &value_map);
	void set_value(const std::string &only_value);
	void set_value(const std::map<std::string, std::string> &value_map);

	////////////////////////////////////////////////////////////////////////

	static Result<int, int> parse_map_element(const std::string &field_value,
											  std::size_t start_pos,
											  std::size_t *end_pos,
											  std::string *key,
											  std::string *value);
	static bool is_key_only(const std::string &value);

 private:
	std::string _only_value;
	std::map<std::string, std::string> _value_map;
};
