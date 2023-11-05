#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include "DeleteHttpResponse.hpp"

#define	EXIST 		0
#define	NO_EXIST	1

// もしかしたらmake_responseとか共通した関数作っといてそこから派生させたほうがいいかも
// ~~があれば、はconfig上にfieldとして存在しているか、という書き方になってる
// 途中で失敗した場合ってその時点でエラーメッセージを作ればいいのか

namespace Config
{
	bool	_autoindex = true;
	bool    _chunked_transferencoding_allow = false;  // 現状使い方わかってない
	int     _server_tokens = 1;
	size_t 	_client_body_buffer_size = 1000;
	size_t  _client_body_timeout = 60;
	size_t  _client_header_buffer_size = 1024;
	size_t  _client_header_timeout = 60;
	size_t  _client_max_body_size = 1024;
	size_t  _keepaliverequests = 10;
	size_t  _keepalive_timeout = 60;
	size_t  _maxBodySize = 2048;
	std::string  _alias = "/www/images";  // 共通 読み込んでくるフォルダを変える
	std::string  _accesslog = "";  // 共通
	std::string  _cgi_path = "";  // 共通
	std::string  _default_type = "text/plain";  // 共通
	std::string  _errorlog = "";
	std::string  _root = "/www";  // 共通aliasより優先度は低い
	std::vector<std::string>	_allowmethod;
}  // namespace Config

namespace Request
{
	// Request全文
	std::string	_request_all_text = "";
	// Request Line
	// std::string	_target_server_name;
	std::string	_method = "GET";
	std::string	_request_path = "/www";
	std::string	_http_version = "1";
	// header
	std::string	_header_text = "";
	// body
	std::string	_body_text = "";
	std::string	_request_body = "";
}  // namespace Request

bool	DeleteHttpResponse::is_request_under_maxsize(const std::string &request_text, const size_t &maxsize)
{
	if (request_text.length() >= maxsize)
	{
		this->_status_code = 400;
		return (false);
	}
	return (true);
}

bool	DeleteHttpResponse::is_header_under_maxsize(const std::string &header_text, const size_t &maxsize)
{
	if (header_text.length() >= maxsize)
	{
		this->_status_code = 400;
		return (false);
	}
	return (true);
}

bool	DeleteHttpResponse::is_body_under_maxsize(const std::string &body_text, const size_t &maxsize)
{
	if (body_text.length() >= maxsize)
	{
		this->_status_code = 400;
		return (false);
	}
	return (true);
}

bool DeleteHttpResponse::is_method_allowed(const std::vector<std::string> &allowed_method, const std::string &target)
{
	return (std::count(allowed_method.begin(), allowed_method.end(), target) != 0);
}

void	DeleteHttpResponse::ready_status_text_map()  // 返すbodyの中身は該当のファイルの中身でもいいと思う
{
	StatusText status_200("OK", "<h1>OK<h1>");
	StatusText status_400("Not Found", "404 Not Found\r\nResource can't find\r\n\r\n");
	StatusText status_405("Method Not Allowed", "405 Method Not Allowed");
	StatusText status_413("Request Entity Too Large", "413 Request Entity Too Large");

	this->_status_text_map["200"] = status_200;
	this->_status_text_map["400"] = status_400;
	this->_status_text_map["405"] = status_405;
	this->_status_text_map["413"] = status_413;
}

std::string	DeleteHttpResponse::ready_now_time() const
{
	char buffer[128];
	time_t	nowtime = time(NULL);
    tm*		nowtimestruct = NULL;

	gmtime_r(&nowtime, nowtimestruct);
    strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", nowtimestruct);
    return static_cast<std::string>(buffer);
}

void	DeleteHttpResponse::make_response(const std::string &status_code)
{
	this->_response = "HTTP/1.1 " + status_code + " " + this->_status_text_map[status_code].get_status_text() + "\r\n";
	this->_response = this->_response + "Date: " + this->ready_now_time() + "\r\n";
	this->_response = this->_response + "Server: wevserv==^^==\r\n";
	this->_response = this->_response + "Content-Type: text/html;\r\n";
	this->_response = this->_response + "charset=UTF-8\r\n";
	this->_response = this->_response + "Content-Length: 60;\r\n";
	// 本当は　this->_status_text_map[status_code].get_body_text().length()
	this->_response = this->_response + "Connection: close\r\n";
	this->_response = this->_response + "\r\n";
	this->_response = this->_response + this->_status_text_map[status_code].get_body_text();
}

DeleteHttpResponse::DeleteHttpResponse()
{
	this->_status_code = 200;
	Config::_allowmethod.push_back("GET");
	// 該当のconfigをとってくる関数は切り分けてしまう //
	// 以下正しいconfigをとってきたものと仮定する
	// if (!(Config::_accesslog != ""))
	// 	ready_access_log(Config::_accesslog);
	// if (!(Config::_errorlog != ""))
	// 	ready_error_log(Config::_errorlog);
	if (!(is_request_under_maxsize(Request::_request_all_text, Config::_client_max_body_size)))
	{
		this->make_response("413");
		return;
	}
	if (!(is_header_under_maxsize(Request::_header_text, Config::_client_header_buffer_size)))
	{
		this->make_response("413");
		return;
	}
	if (!(is_body_under_maxsize(Request::_request_body, Config::_client_body_buffer_size)))
	{
		this->make_response("413");
		return;
	}
	if (!(Config::_allowmethod).empty())
	{
		if (!(is_method_allowed(Config::_allowmethod, Request::_method)))
		{
			this->make_response("405");
			return;
		}
	}
	// if (!(Config::_server_tokens != ))http_versionの比較　数値を扱う方が必要　1.1だけなら確認する必要はない。。。？
	// バージョン対応していないというステータスコード があったと思うのでそれを置くのもいいかもしれない
}

DeleteHttpResponse::~DeleteHttpResponse(){}
