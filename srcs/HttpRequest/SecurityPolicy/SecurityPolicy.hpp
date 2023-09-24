#ifndef SRCS_HTTPREQUEST_SECURITYPOLICY_SECURITYPOLICY_HPP_
#define SRCS_HTTPREQUEST_SECURITYPOLICY_SECURITYPOLICY_HPP_

#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class SecurityPolicy: public BaseKeyValueMap
{
	private:
		std::string											_report_url;
		std::map<std::string, std::vector<std::string> >	_policy_directive;
	public:
		explicit SecurityPolicy(std::map<std::string, std::vector<std::string> > _policy_directive);
		SecurityPolicy(const std::string &report_url, std::map<std::string, std::vector<std::string> > _policy_directive);
		~SecurityPolicy();
		std::map<std::string, std::vector<std::string> >	get_policy_directhive(void) const;
		std::string											get_reporturl(void) const;
};

#endif  // SRCS_HTTPREQUEST_SECURITYPOLICY_SECURITYPOLICY_HPP_
