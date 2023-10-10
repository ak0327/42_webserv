#include "SecurityPolicy.hpp"

SecurityPolicy::SecurityPolicy(std::map<std::string, std::vector<std::string> >	_policy_directive):FieldValues()
{
	this->_policy_directive = _policy_directive;
}

SecurityPolicy::SecurityPolicy(const std::string &report_url, std::map<std::string, std::vector<std::string> >	_policy_directive)
{
	this->_report_url = report_url;
	this->_policy_directive = _policy_directive;
}

SecurityPolicy::~SecurityPolicy(){}

std::map<std::string, std::vector<std::string> > SecurityPolicy::get_policy_directhive(void) const
{
	return (this->_policy_directive);
}

std::string SecurityPolicy::get_reporturl(void) const
{
	return (this->_report_url);
}
