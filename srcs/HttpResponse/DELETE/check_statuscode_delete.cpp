//100statuscode

#include "testclasss.hpp"
#include <algorithm>
#include <string>
#include <vector>
#include <map>

#include "../TestConfig.hpp"

#define	EXIST 		0
#define	NO_EXIST	1

// もしかしたらmake_responseとか共通した関数作っといてそこから派生させたほうがいいかも
// ~~があれば、はconfig上にfieldとして存在しているか、という書き方になってる
// 途中で失敗した場合ってその時点でエラーメッセージを作ればいいのか

namespace Config
{
	bool	_autoindex = true;
	bool    _chunked_transferencoding_allow = false; //現状使い方わかってない
	int     _server_tokens = 1;
	size_t 	_client_body_buffer_size = 1000;
	size_t  _client_body_timeout = 60;
	size_t  _client_header_buffer_size = 1024;
	size_t  _client_header_timeout = 60;
	size_t  _client_max_body_size = 1024;
	size_t  _keepaliverequests = 10;
	size_t  _keepalive_timeout = 60;
	size_t  _maxBodySize = 2048;
	std::string  _alias = "/www/images"; // 共通 読み込んでくるフォルダを変える
	std::string  _accesslog = ""; // 共通
	std::string  _cgi_path = ""; // 共通
	std::string  _default_type = "text/plain"; // 共通
	std::string  _errorlog = "";
	std::string  _root = "/www"; // 共通　aliasより優先度は低い
	std::vector<std::string>	_allowmethod;
	_allowmethod.push_back("GET");
}

namespace Request
{
	// std::string	_target_server_name;
	std::string	_method = "GET";
	std::string	_request_path = "/www";
	std::string	_http_version = "1";
}

HttpResponse::HttpResponse()
{
	this->_statuscode = 200;

	//該当のconfigをとってくる関数は切り分けてしまう //
	//以下正しいconfigをとってきたものと仮定する
	if (!(Config::_accesslog != ""))
		ready_access_log();
	if (!(Config::_errorlog != ""))
		ready_error_log();
	if (!(Config::_allowmethod).empty())
	{
		if (!(is_method_allowed(Config::_allowmethod, Request::_method)))
		{
			this->
		}
	}
}
