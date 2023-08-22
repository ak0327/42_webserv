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

void	HttpRequest::set_alt_svc(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	if (value.find(';') == std::string::npos)
	{
		while(std::getline(ss, line, ';'))
			value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
		this->_alt_svc.set_value(value_map);
	}
	else
	{
		this->_alt_svc.set_value(HandlingString::skipping_emptyword(line));
	}
}

void	HttpRequest:: set_alt_used(const std::string &value)
{
	std::stringstream	ss(HandlingString::skipping_emptyword(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, ':');
	std::getline(ss, second_value, ':');
	this->_alt_used.set_values(first_value, second_value);
}

void	HttpRequest:: set_authorization(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	if (value.find(',') != std::string::npos)
	{
		while(std::getline(ss, line, ';'))
			value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
		this->_alt_svc.set_value(value_map);
	}
	else
	{
		this->_alt_svc.set_value(HandlingString::skipping_emptyword(line));
	}
}
//この格納方法でいいのかちょっとわからん

//Cache-Controlどう使うのか全くわからない

void	HttpRequest::set_clear_site_data(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_clear_site_data.set_value_array(value_array);
	//ダブルクオーテーションとれ
}

void	HttpRequest::set_connection(const std::string &value)
{
	this->_connection = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_content_disponesition(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	if (value.find(';') != std::string::npos)
	{
		std::string	key;
		std::getline(ss, key, ';');
		while(std::getline(ss, line, ';'))
			value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
		this->_content_disponesition.set_value(key, value_map);
	}
	else
	{
		this->_content_disponesition.set_value(HandlingString::skipping_emptyword(line));
	}
}

void	HttpRequest::set_content_encoding(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_content_encoding.set_value_array(value_array);
}

void	HttpRequest::set_content_language(const std::string &value)
{
	std::vector<std::string>	value_array;

	std::stringstream	ss(value);
	std::string			line;
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_content_language.set_value_array(value_array);
}

void	HttpRequest::set_content_length(const std::string &value)
{
	this->_content_length = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_content_location(const std::string &value)
{
	this->_content_location = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_content_range(const std::string &value)
{
	this->_content_range = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_content_security_policy(const std::string &value)
{
	std::stringstream	ss(HandlingString::skipping_emptyword(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, ';');
	std::getline(ss, second_value, ';');
	this->_content_security_policy.set_values(first_value, second_value);
}

void	HttpRequest::set_content_security_policy_report_only(const std::string &value)
{
	std::stringstream	ss(HandlingString::skipping_emptyword(value));
	std::string			first_value;
	std::string			second_value;

	std::getline(ss, first_value, ';');
	std::getline(ss, second_value, ';');
	this->_content_security_policy_report_only.set_values(first_value, second_value);
}

void	HttpRequest::set_content_type(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;
	std::string	key;

	std::getline(ss, key, ';');
	while(std::getline(ss, line, ';'))
		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	this->_content_type.set_value(key, value_map);
}

void	HttpRequest::set_cookie(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	this->_content_type.set_value(value_map);
}

void	HttpRequest::set_cross_origin_embedder_policy(const std::string &value)
{
	this->_cross_origin_embedder_policy = HandlingString::skipping_emptyword(value);
}

void	HttpReques::set_cross_origin_opener_policy(const std::string &value)
{
	this->_cross_origin_opener_policy = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_cross_origin_resource_policy(const std::string &value)
{
	this->_cross_origin_resource_policy = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_date(const std:string &value)
{
	
}

void	HttpRequest::set_etag(const std::string &value)
{
	this->_etag = HandlingString::skipping_emptyword(value);
}

void	Httprequest::set_expect(const std::string &value)
{
	this->_expect = HandlingString::skipping_emptyword(value);
}

//expect-ctは現状廃止されているっぽくて対応したくない

void	HttpRequest::set_expires(const std::string &value)
{

}

void	HttpRequest::set_forwarded(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ';'))
		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	this->_forwarded.set_value(value_map);
}

void	HttpRequest::set_email(const std::string &value)
{

}//?

void	HttpRequest::set_from(const std::string &value)
{
	this->_form = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_host(const std::string &value)
{
	std::stringstream	ss(HandlingString::skipping_emptyword(value));
	std::string			first_value;
	std::string			second_value;

	if (value.find(':') != std::string::npos)
	{
		std::getline(ss, first_value, ':');
		std::getline(ss, second_value, ':');
		this->_alt_used.set_values(first_value, second_value);
	}
	else
	{
		this->_alt_used.set_values(HandlingString::skipping_emptyword(value));
	}
}

void	HttpRequest::set_if_match(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_if_match.set_value_array(value_array);
}

void	Httprequest::set_if_modified_since(const std::string &value)
{
	
}

void	HttpRequest::set_if_none_match(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_if_none_match.set_value_array(value_array);
}

void	Httprequest::set_if_range(const std::string &value)
{

}

void	Httprequest::set_if_unmodified_since(const std::string &value)
{

}

void	HttpRequest::set_keepalive(const std::string &value)
{
	this->_keepalive = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_last_modified(const std::string &value)
{

}

void	HttpRequest::set_link(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	std::string	key;
	std::getline(ss, key, ';');
	while(std::getline(ss, line, ';'))
		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	this->_content_disponesition.set_value(key, value_map);
}

void	HttpRequest::set_location(const std::string &value)
{
	this->_location = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_max_forwards(const std::string &value)
{
	this->_max_forwards = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_origin(const std::string &value)
{
	this->_origin = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_permission_policy(const std::string &value)
{
	// std::stringstream	ss(HandlingString::skipping_emptyword(value));
	// std::string			first_value;
	// std::string			second_value;

	// std::getline(ss, first_value, ' ');
	// std::getline(ss, second_value, '/');
	// this->_accept_post.set_values(first_value, second_value);
	//空白が分割文字だからそのまま使うとまずい
}

void	Httprequest::set_proxy_authenticate(const std::string &value)
{
	// std::map<std::string, std::string> value_map;
	// std::stringstream	ss(value);
	// std::string			line;

	// if (value.find(';') == std::string::npos)
	// {
	// 	while(std::getline(ss, line, ';'))
	// 		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	// 	this->_alt_svc.set_value(value_map);
	// }
	// else
	// {
	// 	this->_alt_svc.set_value(HandlingString::skipping_emptyword(line));
	// }
	//これも空白文字が分割に使われてるからまずい
}

void	HttpRequest::set_proxy_authorization(const std::string &value)
{
	//空白が分割文字だからそのまま使うとまずい
}

//range何かよくわからん

void	HttpRequest::set_referer(const std::string &value)
{
	this->_referer = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_referrer_policy(const std::string &value)
{
	this->_referrer_policy = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_retry_after(const std::string &value)
{
	this->_retry_after = HandlingString::skipping_emptyword(value);
	//やばいこいつ普通の値とDate型の値持ちやがる
}

void	HttpRequest::set_sec_fetch_dest(const std::string &value)
{
	this->_sec_fetch_dest = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_sec_fetch_mode(const std::string &value)
{
	this->_sec_fetch_mode = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_sec_fetch_site(const std::string &value)
{
	this->_sec_fetch_site = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_sec_fetch_user(const std::string &value)
{
	this->_sec_fetch_user = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_sec_purpose(const std::string &value)
{
	this->_sec_purpose = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_sec_websocket_accept(const std::string &value)
{

}

void	HttpRequest::set_server(const std::string &value)
{

}

void	HttpRequest::set_servertiming(const std::string &value)
{

}

void	HttpRequest::set_service_worker_navigation_preload(const std::string &value)
{

}

void	HttpRequest::set_set_cookie(const std::string &value)
{

}

void	HttpRequest::set_sourcemap(const std::string &value)
{

}

void	HttpRequest::set_strict_transport_security(const std::string &value)
{

}

void	HttpRequest::set_te(const std::string &value)
{

}

void	HttpRequest::set_timing_allow_origin(const std::string &value)
{

}

void	HttpRequest::set_trailer(const std::string &value)
{

}

void	HttpRequest::set_transfer_encoding(const std::string &value)
{

}

void	HttpRequest::set_upgrade(const std::string &value)
{

}

void	HttpRequest::set_upgrade_insecure_requests(const std::string &value)
{

}

void	HttpRequest::set_user_agent(const std::string &value)
{

}

void	HttpRequest::set_vary(const std::string &value)
{

}

void	HttpRequest::set_via(const std::string &value)
{

}

void	HttpRequest::set_www_authenticate(const std::string &value)
{

}

void	HttpRequest::set_x_xss_protection(const std::string &value)
{

}