#include "../includes/HttpRequest.hpp"

HttpRequest::HttpRequest(const std::string &value)
{
	std::string	line;
	std::string	key;

	std::stringstream ss(value);
	std::getline(ss, line, '\n');
	this->_requestline.set_value(line);
	while (std::getline(ss, line, '\n'))
	{
        key = this->obtain_request_key(line);
		if (this->check_keyword_exist(key) == true)
		{

		}
    }
}

std::string HttpRequest::obtain_request_key(const std::string value)
{
	std::stringstream	ss(value);
	std::string			line;

	std::getline(ss, line, ':');
	return (line);
}

std::string HttpRequest::obtain_request_value(const std::string value)
{
	std::stringstream	ss(value);
	std::string			line;

	std::getline(ss, line, ':');
	std::getline(ss, line, ':');
	return (line.substr(1));
}

HttpRequest::~HttpRequest()
{

}

bool HttpRequest::check_keyword_exist(const std::string &key)
{
	const std::string httprequest_keyset_arr[] = {
		"Host",
		"Connection",
		"Referer", "Content-Type", "Range", "Upgrade", "Accept-Encoding", "Via", "Keep-Alive", "Accept-Language", "Accept", "Date",
		"Cookie",
		"If-Modified-Since", "If-Unmodified-Since","If-Match","If-None-Match","Content-Length","Content-Range","If-Range","Transfer-Encoding",
		"Expect","Authorization","User-Agent",

        "Accept-CH", "Accept-Charset", "Accept-Patch", "Accept-Ranges", "Access-Control-Allow-Credentials",
		"Access-Control-Allow-Headers", "Access-Control-Allow-Methods", "Access-Control-Allow-Origin", "Access-Control-Expose-Headers", "Access-Control-Max-Age",
		"Access-Control-Request-Headers", "Access-Control-Request-Method", "Age", "Allow", "Alt-Svc", "Cache-Control", "Clear-Site-Data",
		"Content-Disposition", "Content-Encoding", "Content-Language", "Content-Location", "Content-Security-Policy",
		"Content-Security-Policy-Report-Only", "Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
	 	"ETag", "Expect-CT", "Expires", "Forwarded", "From",
		"Last-Modified", "Location", "Origin", "Permissions-Policy", "Proxy-Authenticate", "Proxy-Authorization", "Referrer-Policy",
		"Retry-After", "Server", "Server-Timing", "Set-Cookie", "SourceMap", "Timing-Allow-Origin",
		"Upgrade-Insecure-Requests", "Vary", "WWW-Authenticate"
    };

    const std::set<std::string> httprequest_keyset
    (
        httprequest_keyset_arr,
        httprequest_keyset_arr + sizeof(httprequest_keyset_arr) / sizeof(httprequest_keyset_arr[0])
    );

    if (httprequest_keyset.count(key) > 0)
        return true;
    return false;
}

void	HttpRequest::set_accept(const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line.find(';') != std::string::npos)
			this->_accept.append_valueweight_set(HandlingString::skipping_emptyword(line));
		else
			this->_accept.append_valueweight_set(HandlingString::skipping_emptyword(line), 1.0);
	}
}//命名規則はMDN上に乗っている名前の前に_をつけることで対応していく、ただし大文字は全て小文字に変更して対応するものとする//要相談

void	HttpRequest::set_accept_ch(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_accept_ch.set_value_array(value_array);
}//ハイフンは_にしちゃいたいかも

//初期化に引数を必ず取りたいため、引数なしのコンストラクタは許可したくなく、privateに避難しているがこれだとダメっぽい？ちゃうんかい
void	HttpRequest::set_accept_charset(const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line.find(';') != std::string::npos)
			this->_accept_charset.append_valueweight_set(HandlingString::skipping_emptyword(line));
		else
			this->_accept_charset.append_valueweight_set(HandlingString::skipping_emptyword(line), 1.0);
	}
}

void	HttpRequest::set_accept_encoding(const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line.find(';') != std::string::npos)
			this->_accept_encoding.append_valueweight_set(HandlingString::skipping_emptyword(line));
		else
			this->_accept_encoding.append_valueweight_set(HandlingString::skipping_emptyword(line), 1.0);
	}
}

void	HttpRequest::set_accept_language(const std::string &value)
{
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line.find(';') != std::string::npos)
			this->_accept_language.append_valueweight_set(HandlingString::skipping_emptyword(line));
		else
			this->_accept_language.append_valueweight_set(HandlingString::skipping_emptyword(line), 1.0);
	}
}

//Accept-Patchどういう持ち方かわからん

void	HttpRequest::set_accept_post(const std::string &value)
{
	std::stringstream	ss(HandlingString::skipping_emptyword(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, '/');
	std::getline(ss, second_value, '/');
	this->_accept_post.set_values(first_value, second_value);
}

void	HttpRequest::set_accept_ranges(const std::string &value)
{
	this->_accept_ranges.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_access_control_allow_credentials(const std::string &value)
{
	this->_accept_ranges.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_access_control_allow_headers(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_access_control_allow_headers.set_value_array(value_array);
}

void	HttpRequest::set_access_control_allow_methods(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_access_control_allow_methods.set_value_array(value_array);
}

void	HttpRequest::set_access_control_allow_origin(const std::string &value)
{
	this->_access_control_allow_origin.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_access_control_expose_headers(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_access_control_expose_headers.set_value_array(value_array);
}

void	HttpRequest::set_access_control_max_age(const std::string &value)
{
	this->_access_control_max_age.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_access_control_request_headers(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_access_control_request_headers.set_value_array(value_array);
}

void	HttpRequest::set_access_control_request_method(const std::string &value)
{
	this->_access_control_request_method.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_age(const std::string &value)
{
	this->_age.set_value(HandlingString::skipping_emptyword(value));
}

void	HttpRequest::set_allow(const sts::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_allow.set_value_array(value_array);
}

//Alt-Svc値どう使うのか全くわからない

void	HttpRequest::set_authorization(const std::string &value)
{

}

//Cache-Controlどう使うのか全くわからない

void	HttpRequest::set_clear_site_data(const std::string &value)
{

}

//connectionは危険っぽいので無視していいっすか？

//content_disponesitionは特殊なクラスを与えた方が良さそう

void	HttpRequest::set_content_encoding(const std::string &value)
{

}

void	HttpRequest::set_content_language(const std::string &value)
{

}

void	HttpRequest::set_content_length(const std::string &value)
{

}

void	HttpRequest::set_content_location(const std::string &value)
{

}

//content-rangeは特殊なクラスを与えた方が良さそう

//content-security-policyよくわからん

//content-security-policy-report-onlyよくわからん

//content-typeは特殊なクラスを与えた方が良さそう

//cookieは特殊なクラスを与えた方が良さそう

void	HttpRequest::set_cross_origin_embedder_policy(const std::string &value)
{

}

void	HttpRequest::set_cross_origin_opener_policy(const std::string &value)
{

}

//Cross-Origin=Resource-Policyはバグあるっぽくて対応したくない

void	HttpRequest::set_date(const std:string &value)
{

}

void	HttpRequest::set_etag(const std::string &value)
{

}

void	HttpRequest::set_expect(const std::string &value)
{

}

//expect-ctは現状廃止されているっぽくて対応したくない

void	HttpRequest::set_expires(const std::string &value)
{

}

//Forwardedは特殊なクラスを与えた方がいいかも

void	HttpRequest::set_email(const std::string &value)
{

}

//Hostは特殊なクラスを与えた方がいいかも

void	HttpRequest::set_if_match(const std::string &value)
{

}

void	HttpRequest::set_if_modified_since(const std::string &value)
{

}

void	HttpRequest::set_if_none_match(const std::string &value)
{

}

void	HttpRequest::set_if_range(const std::string &value)
{

}

void	HttpRequest::set_if_unmodified_since(const std::string &value)
{

}

//keepaliveは危険らしく対応したくない

void	HttpRequest::set_last_modified(const std::string &value)
{

}

//Linkは特殊なクラスを持たせたほうがいいかも

void	HttpRequest::set_location(const std::string &value)
{

}

//Originは特殊なクラスを持たせたほうがいいかも

//permission-policy何してるのかよくわからん

//proxy-authenticateは特殊なクラスを持たせたほうがいいかも

//proxy-authorizationは特殊なクラスを持たせたほうがいいかも

//range何かよくわからん

//refererに関しては危険っぽいので対応したくない

void	HttpRequest::set_referrer_policy(const std::string &value)
{

}

void	HttpRequest::set_retry_after(const std::string &value)
{

}

void	HttpRequest::set_server(const std::string &value)
{

}

//servertimingよくわからん

//set-cookieよくわからん　そもそもcookieってなんだよお菓子かよ

void	HttpRequest::set_sourcemap(const std::string &value)
{

}

void	HttpRequest::set_timing_allow_origin(const std::string &value)
{

}

void	HttpRequest::set_transfer_encoding(const std::string &value)
{

}

//upgradeも対応したくない

void	HttpRequest::set_upgrade_insecure_requests(const std::string &value)
{

}

//User-Agentは特殊なクラスを持たせたほうがいいかも

void	HttpRequest::set_vary(const std::string &value)
{

}

//Viaは特殊なクラスを持たせたほうがいいかも

void	HttpRequest::set_www_authenticate(const std::string &value)
{

}

void	HttpRequest::set_x_content_type_options(const std::string &value)
{

}

void	HttpRequest::set_x_frame_options(const std::string &value)
{

}

static	httprequest_key_functions(const std::string &key)
{
	std::map<std::string, void(*)()> functionMap;
}