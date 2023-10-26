#pragma once

# include <map>
# include <set>
# include <string>
# include "FieldValueBase.hpp"
# include "Result.hpp"

class MapSetFieldValues : public FieldValueBase {
 public:
	explicit MapSetFieldValues(const std::set<std::map<std::string, std::string> > &values);
	virtual ~MapSetFieldValues();

	MapSetFieldValues(const MapSetFieldValues &other);
	MapSetFieldValues &operator=(const MapSetFieldValues &rhs);

	std::set<std::map<std::string, std::string> > get_map_set_values() const;

	static Result<std::set<std::map<std::string, std::string> >, int>
	parse_map_set_field_values(const std::string &field_value,
							   Result<std::map<std::string, std::string>, int> (*parse_func)(const std::string &,
									   														 std::size_t,
																							 std::size_t *));

 private:
	std::set<std::map<std::string, std::string> > _map_set_values;
};
