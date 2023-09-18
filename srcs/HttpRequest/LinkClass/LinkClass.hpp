#ifndef SRCS_HTTPREQUEST_LINKCLASS_LINKCLASS_HPP_
#define SRCS_HTTPREQUEST_LINKCLASS_LINKCLASS_HPP_

#include <map>
#include <string>

#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class LinkClass: public BaseKeyValueMap
{
	private:
		std::map<std::string, std::map<std::string, std::string> > _link_valuemap;
	public:
		explicit LinkClass(std::map<std::string, std::map<std::string, std::string> > link_valuemap);
		virtual ~LinkClass();
		std::map<std::string, std::map<std::string, std::string> >	get_link_valuemap(void) const;
		void show_value(){}
};

#endif  // SRCS_HTTPREQUEST_LINKCLASS_LINKCLASS_HPP_
