#include "../includes/HttpRequest.hpp"

//constructor
HttpRequest::HttpRequest()
{
	//~~//
}

HttpRequest::HttpRequest(const std::string &other)
{
	std::istringstream				lines(other);
	std::string						one_line;

	while (std::getline(lines, one_line))
		this->_httprequest_infs[this->obtain_key(one_line)] = this->obtain_value(one_line);
}

HttpRequest::HttpRequest(const HttpRequest& other)
{
	this->_httprequest_infs = other.return_httprequest_infs();
}

HttpRequest& HttpRequest::operator=(const HttpRequest& other)
{
	if (this == &other)
		return (*this);
	this->_httprequest_infs = other.return_httprequest_infs();
	return (*this);
}

//destructor
HttpRequest::~HttpRequest()
{

}

// void HttpRequest::check_httprequest_keyword(const std::string &keyword)
// {
// 	const std::string httprequest_keyset_arr[] = {
//         "User-Agent", "ANY OTHER WORD"
//     };

//     const std::set<std::string> httprequest_keyset
//     (
//         httprequest_keyset_arr,
//         httprequest_keyset_arr + sizeof(httprequest_keyset_arr) / sizeof(httprequest_keyset_arr[0])
//     );

//     if (httprequest_keyset.count(keyword) > 0)
//         set_specialhttprequestkeyword(keyword);
// 	else
// 		set_httprequestkeyword(keyword);
// }

// void HttpRequest::set_specialhttprequestkeyword(const std::string &keyword)
// {
// 	if (keyword == "User-Agent")
// 	{
// 		this->
// 	}
// }

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
			value_set.set_value(one_line);
			value_set.set_weight(1.0);
		}
		else
		{
			value_set.set_value(HandlingString::obtain_beforeword(one_line, ';'));
			value_set.set_weight(HandlingString::obtain_afterword(HandlingString::obtain_afterword(one_line, ';'), '='));
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
	while (it != this->_httprequest_infs.end())
	{
		std::cout << "KEY is >> " << BLUE_COLOR << it->first << RESET_COLOR << " <<" << std::endl;
		std::vector<Requestvalue_set>::iterator it_vec = it->second.begin();
		while (it_vec != it->second.end())
		{
			std::cout  << "# # # # # # # # # # # # # # #" << std::endl;
			std::cout << MAGENTA_COLOR << "VALUE is >> " << (*it_vec).get_value()  << " | ";
			std::cout << "VALUE WEIGHT is >> " << (*it_vec).get_weight() << RESET_COLOR << std::endl;
			it_vec++;
		}
		it++;
	}
}