#ifndef VALUEMAP_HPP
#define VALUEMAP_HPP

#include <string>
#include <map>

class ValueMap
{
	private:
		std::string							_only_value;
		std::map<std::string, std::string>	_value_map;
		ValueMap(const ValueMap &other);
		ValueMap& operator=(const ValueMap &other);
	
	public:
		ValueMap();
		ValueMap(const std::string &value);
		~ValueMap();

		void	set_only_value(const std::string &value);
		void	set_value_map(const std::string &value);

		std::string							get_only_value(void) const;
		std::map<std::string, std::string>	get_value_map(void) const;
};

#endif