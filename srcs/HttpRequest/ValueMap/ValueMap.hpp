#ifndef SRCS_HTTPREQUEST_VALUEMAP_VALUEMAP_HPP_
#define SRCS_HTTPREQUEST_VALUEMAP_VALUEMAP_HPP_

# include <iostream>
# include <map>
# include <string>
# include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class ValueMap: public BaseKeyValueMap
{
	private:
		std::string							_only_value;
		std::map<std::string, std::string>	_value_map;
	public:
		ValueMap();
		ValueMap(const ValueMap &other);
		ValueMap& operator=(const ValueMap &other);
		ValueMap(const std::string &value, std::map<std::string, std::string> value_map);
		explicit ValueMap(std::map<std::string, std::string> value_map);
		~ValueMap();
		std::string							get_only_value(void) const;
		std::map<std::string, std::string>	get_value_map(void) const;
		void								set_value(const std::string &only_value, const std::map<std::string, std::string> &value_map);
		void								set_value(const std::string &only_value);
		void								set_value(const std::map<std::string, std::string> &value_map);
};

#endif  // SRCS_HTTPREQUEST_VALUEMAP_VALUEMAP_HPP_
