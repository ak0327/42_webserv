#include "LinkClass.hpp"

LinkClass::LinkClass(std::map<std::string, std::map<std::string, std::string> > link_valuemap)
{
	this->_link_valuemap = link_valuemap;
}

LinkClass::~LinkClass(){}

std::map<std::string, std::map<std::string, std::string> >	LinkClass::get_link_valuemap(void) const
{
	return (this->_link_valuemap);
}
