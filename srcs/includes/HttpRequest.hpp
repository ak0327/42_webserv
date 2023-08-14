#ifndef HTTPREQUEST_HPP
#define HTTPREQUEST_HPP

#include <map>
#include <string>

class HttpRequest
{
	private:
		std::map<std::string, std::string>	_httprequest_infs;//ここにリクエストできたkeyとvalueを格納していく

		std::string							_refaral_path;//configの情報を参照していく
		// LocationConf						_locationinfs;//各リクエストないにconfigにて参照する情報を持たす？しかしそれは大きくなりすぎているのでは
		//httprequestの内部で情報の順位付けを許可するならstd::string 型ではよくない気がしている
		//一旦ここに関して格納することにして後ほど使う際にうまいこと分割を行うことにしてしまっても良いし、この時点で分割して情報を格納してしまってもいいかもしれない　要相談
	
	public:
		HttpRequest();
		HttpRequest(const std::string&);
		~HttpRequest();
		HttpRequest(const HttpRequest &other);
		HttpRequest &operator=(const HttpRequest &other);

		std::map<std::string, std::string>	return_httprequest_infs(void) const;
		std::string							return_value(const std::string key);//keyを与えるとそれに相当するvalueを返すような関数

		void								split_key_value(const std::string &other);

		std::string							obtain_key(const std::string other);
		std::string							obtain_value(const std::string other);
};

#endif