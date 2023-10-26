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

 private:
	std::set<std::map<std::string, std::string> > _map_set_values;
};
