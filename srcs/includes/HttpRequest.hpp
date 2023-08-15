#ifndef HTTPREQUEST_HPP
#define HTTPREQUEST_HPP

#include <map>
#include <string>
#include <vector>
#include <sstream>

#include "Requestvalue_set.hpp"
#include "HandlingString.hpp"

class Requestvalue_set;

class HttpRequest
{
	private:
		std::map<std::string, std::vector<Requestvalue_set> >	_httprequest_infs;//ここにリクエストできたkeyとvalueを格納していく

		//std::string							_refaral_path;//configの情報を参照していく
		// LocationConf						_locationinfs;//各リクエストないにconfigにて参照する情報を持たす？しかしそれは大きくなりすぎているのでは
		//httprequestの内部で情報の順位付けを許可するならstd::string 型ではよくない気がしている
		//一旦ここに関して格納することにして後ほど使う際にうまいこと分割を行うことにしてしまっても良いし、この時点で分割して情報を格納してしまってもいいかもしれない　要相談
	
	public:
		HttpRequest();
		HttpRequest(const std::string&);
		~HttpRequest();
		HttpRequest(const HttpRequest &other);
		HttpRequest &operator=(const HttpRequest &other);

		std::map<std::string, std::vector<Requestvalue_set> >	return_httprequest_infs(void) const;
		std::vector<Requestvalue_set>							return_value(const std::string key);//keyを与えるとそれに相当するvalueを返すような関数

		std::string							obtain_key(const std::string other);
		std::vector<Requestvalue_set>		obtain_value(const std::string other);
		std::vector<Requestvalue_set>		obtain_value_with_coron(const std::string other);

		//debug関数
		void show_requestinfs(void);
};

#endif