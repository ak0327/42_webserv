#include "../includes/HttpRequest.hpp"

//constructor
HttpRequest::HttpRequest()
{
	//~~//
}

HttpRequest::HttpRequest(const std::string &other)
{
	std::string	key = this->obtain_key(other);


}

HttpRequest::HttpRequest(const HttpRequest& other)
{

}

HttpRequest& HttpRequest::operator=(const HttpRequest& other)
{

}

//destructor
HttpRequest::~HttpRequest()
{

}

//public関数

std::string HttpRequest::obtain_key(const std::string other)
{
	return other.substr(0, other.find(':'));
}

std::vector<Requestvalue_set> HttpRequest::obtain_value(const std::string other)
{
	std::vector<Requestvalue_set>	reqestvalue_set_vector;

	std::string all_value = other.substr(other.find(':') + 1);
	if (all_value.find(',') == std::string::npos)
	{
		Requestvalue_set some(all_value);
		reqestvalue_set_vector.push_back(some);
		return (reqestvalue_set_vector);
	}
	else
		return (this->obtain_value_with_coron(all_value));
}

std::vector<Requestvalue_set> HttpRequest::obtain_value_with_coron(const std::string other)
{
	std::vector<Requestvalue_set>	all_value_set;
	std::istringstream				lines(other);
	std::string						one_line;
	Requestvalue_set				value_set;
	
	while (std::getline(lines, one_line, ','))
	{
		if (one_line.find(';') == std::string::npos)
		{
			value_set.set_value(other);
			value_set.set_weight(1.0);
		}
		else
		{
			value_set.set_value(HandlingString::obtain_beforeword(other, ';'));
			value_set.set_weight(HandlingString::str_to_double(HandlingString::obtain_afterword(other, ';')));
		}
		all_value_set.push_back(value_set);
		value_set.clear_membervariable();
	}
	return (all_value_set);
}

std::map<std::string, std::vector<Requestvalue_set> > HttpRequest::return_httprequest_infs(void) const
{
	return (this->_httprequest_infs);
}

std::vector<Requestvalue_set> HttpRequest::return_value(const std::string key)
{
	return (this->_httprequest_infs[key]);
}

#define RESET_COLOR "\033[0m"
#define RED_COLOR "\033[31m"
#define GREEN_COLOR "\033[32m"
#define YELLOW_COLOR "\033[33m"
#define BLUE_COLOR "\033[34m"
#define MAGENTA_COLOR "\033[35m"
#define CYAN_COLOR "\033[36m"

void HttpRequest::show_requestinfs(void)
{
	std::map<std::string, std::vector<Requestvalue_set> >::iterator	it = this->_httprequest_infs.begin();
	std::cout << RED_COLOR << "============  SHOW VALUE   ============" << RESET_COLOR << std::endl;
	std::cout << "KEY is >> " << BLUE_COLOR << it->first << RESET_COLOR << " <<";
	while (it != this->_httprequest_infs.end())
	{
		std::vector<Requestvalue_set>::iterator it_vec = it->second.begin();
		while (it_vec != it->second.end())
		{
			std::cout << MAGENTA_COLOR << "# # # # # # # # # # # # # # #" << std::endl;
			std::cout << "VALUE is >> " << (*it_vec).get_value() << " <<";
			std::cout << "VALUE WEIGHT is >> " << (*it_vec).get_weight() << " <<" << RESET_COLOR << std::endl;
			it_vec++;
		}
		it++;
	}
}