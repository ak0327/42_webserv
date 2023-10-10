#include "HttpRequest.hpp"

// security policyクラス

std::vector<std::string>	HttpRequest::securitypolicy_readyvector(const std::string &words)
{
	std::vector<std::string>	tmp_vector;
	std::string	skippingfirstemptyword;
	std::string			line;

	if (words[0] == ' ')
		skippingfirstemptyword = words.substr(1);
	else
		skippingfirstemptyword = words;

	std::stringstream	ss(skippingfirstemptyword);

	while(std::getline(ss, line, ' '))
		tmp_vector.push_back(line);
	return (tmp_vector);
}

SecurityPolicy* HttpRequest::ready_SecurityPolicy(const std::string &report_url, std::map<std::string, std::vector<std::string> >	_policy_directive)
{
	return (new SecurityPolicy(report_url, _policy_directive));
}

SecurityPolicy* HttpRequest::ready_SecurityPolicy(std::map<std::string, std::vector<std::string> >	_policy_directive)
{
	return (new SecurityPolicy(_policy_directive));
}

// todo: Content-Security-Policy
void	HttpRequest::set_content_security_policy(const std::string &key, const std::string &value)
{
	std::map<std::string, std::vector<std::string> > content_security_map;
	std::stringstream	ss(value);
	std::string			line;
	std::string			skip_emptyword;
	std::string			policy_directive;
	std::string			words;
	size_t				empty_position;

	while(std::getline(ss, line, ';'))
	{
		if (line[0] == ' ')
			skip_emptyword = line.substr(1);
		else
			skip_emptyword = line;
		empty_position = skip_emptyword.find(' ');
		policy_directive = skip_emptyword.substr(0, empty_position);
		words = skip_emptyword.substr(empty_position + 1);
		content_security_map[policy_directive] = securitypolicy_readyvector(words);
	}
	this->_request_header_fields[key] = this->ready_SecurityPolicy(content_security_map);
}
