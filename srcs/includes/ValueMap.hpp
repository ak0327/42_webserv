#ifndef VALUEMAP_HPP
#define VALUEMAP_HPP

#include <string>
#include <map>

class ValueMap: public KeyValueMap
{
	private:
		std::string							_only_value;
		std::map<std::string, std::string>	_value_map;
		ValueMap();
		ValueMap(const ValueMap &other);
		ValueMap& operator=(const ValueMap &other);
	
	public:
		ValueMap(std::map<std::string, std::string> value_map);
		~ValueMap();

		void	set_value(const std::string &only_value, const std::map<std::string, std::string> &value_map);
		void	set_value(const std::string &only_value);
		void	set_value(const std::map<std::string, std::string> &value_map);

		std::string							get_only_value(void) const;
		std::map<std::string, std::string>	get_value_map(void) const;
};

#endif