#include "../includes/HttpRequest.hpp"

HttpRequest::HttpRequest(const std::string &value)
{
	std::string	line;
	std::string	key;

	ready_functionmap();
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

void	HttpRequest::ready_functionmap() const
{
	this->inputvalue_functionmap["Accept"] = this->set_accept;
	this->inputvalue_functionmap["Accept-CH"] = this->set_accept_ch;
	this->inputvalue_functionmap["Accept-Charset"] = this->set_accept_charset;
	this->inputvalue_functionmap["Accept-Encoding"] = this->set_accept_encoding;
	this->inputvalue_functionmap["Accept-Language"] = this->set_accept_language;
	//this->inputvalue_functionmap["Accept-Patch"] = this->set_accept_patch;
	this->inputvalue_functionmap["Accept-Post"] = this->set_accept_post;
	this->inputvalue_functionmap["Accept-Ranges"] = this->set_accept_ranges;
	this->inputvalue_functionmap["Access-Control-Allow-Credentials"] = this->set_access_control_allow_credentials;
	this->inputvalue_functionmap["Access-Control-Allow-Headers"] = this->set_access_control_allow_headers;
	this->inputvalue_functionmap["Access-Control-Allow-Methods"] = this->set_access_control_allow_methods;
	this->inputvalue_functionmap["Access-Control-Allow-Origin"] = this->set_access_control_allow_origin;
	this->inputvalue_functionmap["Access-Control-Expose-Headers"] = this->set_access_control_expose_headers;
	this->inputvalue_functionmap["Access-Control-Max-Age"] = this->set_access_control_max_age;
	this->inputvalue_functionmap["Access-Control-Request-Headers"] = this->set_access_control_request_headers;
	this->inputvalue_functionmap["Access-Control-Request-Method"] = this->set_access_control_request_method;
	this->inputvalue_functionmap["Age"] = this->set_age;
	this->inputvalue_functionmap["Allow"] = this->set_allow;
	this->inputvalue_functionmap["Alt-Svc"] = this->set_alt_svc;
	this->inputvalue_functionmap["Alt-Used"] = this->set_alt_used;
	this->inputvalue_functionmap["Authorization"] = this->set_authorization;
	// this->inputvalue_functionmap["Cache-Control"] = this->set_cache_control;
	this->inputvalue_functionmap["Clear-Site-Data"] = this->set_clear_site_data;
	this->inputvalue_functionmap["Connection"] = this->set_connection;
	this->inputvalue_functionmap["Content-Disposition"] = this->set_content_disponesition;
	this->inputvalue_functionmap["Content-Encoding"] = this->set_content_encoding;
	this->inputvalue_functionmap["Content-Language"] = this->set_content_language;
	this->inputvalue_functionmap["Content-Length"] = this->set_content_length;
	this->inputvalue_functionmap["Content-Location"] = this->set_content_location;
	this->inputvalue_functionmap["Content-Range"] = this->set_content_range;
	this->inputvalue_functionmap["Content-Security-Policy"] = this->set_content_security_policy;
	this->inputvalue_functionmap["Content-Security-Policy-Report-Only"] = this->set_content_security_policy_report_only;
	this->inputvalue_functionmap["Content-Type"] = this->set_content_type;
	this->inputvalue_functionmap["Cookie"] = this->set_cookie;
	this->inputvalue_functionmap["Cross-Origin-Embedder-Policy"] = this->set_cross_origin_embedder_policy;
	this->inputvalue_functionmap["Cross-Origin-Opener-Policy"] = this->set_cross_origin_opener_policy;
	this->inputvalue_functionmap["Cross-Origin-Resource-Policy"] = this->set_cross_origin_resource_policy;
	this->inputvalue_functionmap["Date"] = this->set_date;
	this->inputvalue_functionmap["ETag"] = this->set_etag;
	this->inputvalue_functionmap["Expect"] = this->set_expect;
	// this->inputvalue_functionmap["Expect-CT"] = this->set_expect_ct;
	this->inputvalue_functionmap["Expires"] = this->set_expires;
	this->inputvalue_functionmap["Forwarded"] = this->set_forwarded;
	this->inputvalue_functionmap["From"] = this->set_from;
	this->inputvalue_functionmap["Host"] = this->set_host;
	this->inputvalue_functionmap["If-Match"] = this->set_if_match;
	this->inputvalue_functionmap["If-Modified-Since"] = this->set_if_modified_since;
	this->inputvalue_functionmap["If-None-Match"] = this->set_if_none_match;
	this->inputvalue_functionmap["If-Range"] = this->set_if_range;
	this->inputvalue_functionmap["If-Unmodified-Since"] = this->set_if_unmodified_since;
	this->inputvalue_functionmap["Keep-Alive"] = this->set_keepalive;
	this->inputvalue_functionmap["Last-Modified"] = this->set_last_modified;
	this->inputvalue_functionmap["Link"] = this->set_link;
	this->inputvalue_functionmap["Location"] = this->set_location;
	this->inputvalue_functionmap["Max-Forwards"] = this->set_max_forwards;
	this->inputvalue_functionmap["Origin"] = this->set_origin;
	this->inputvalue_functionmap["Permissions-Policy"] = this->set_permission_policy;
	this->inputvalue_functionmap["Proxy-Authenticate"] = this->set_proxy_authenticate;
	this->inputvalue_functionmap["Proxy-Authorization"] = this->set_proxy_authorization;
	// this->inputvalue_functionmap["Range"] = this->set_range;
	this->inputvalue_functionmap["Referer"] = this->set_referer;
	this->inputvalue_functionmap["Retry-After"] = this->set_retry_after;
	this->inputvalue_functionmap["Sec-Fetch-Dest"] = this->set_sec_fetch_dest;
	this->inputvalue_functionmap["Sec-Fetch-Mode"] = this->set_sec_fetch_mode;
	this->inputvalue_functionmap["Sec-Fetch-Site"] = this->set_sec_fetch_site;
	this->inputvalue_functionmap["Sec-Fetch-User"] = this->set_sec_fetch_user;
	this->inputvalue_functionmap["Sec-Purpose"] = this->set_sec_purpose;
	this->inputvalue_functionmap["Sec-WebSocket-Accept"] = this->set_sec_websocket_accept;
	this->inputvalue_functionmap["Server"] = this->set_server;
	// this->inputvalue_functionmap["Server-Timing"] = this->set_server_timing;
	this->inputvalue_functionmap["Service-Worker-Navigation-Preload"] = this->set_server_worker_navigation_preload;
	this->inputvalue_functionmap["Set-Cookie"] = this->set_cookie;
	this->inputvalue_functionmap["SourceMap"] = this->set_sourcemap;
	this->inputvalue_functionmap["Strict-Transport-Security"] = this->set_strict_transport_security;
	this->inputvalue_functionmap["TE"] = this->set_te;
	this->inputvalue_functionmap["Timing-Allow-Origin"] = this->set_timing_allow_origin;
	this->inputvalue_functionmap["Trailer"] = this->set_trailer;
	this->inputvalue_functionmap["Transfer-Encoding"] = this->set_transfer_encoding;
	this->inputvalue_functionmap["Upgrade"] = this->set_upgrade;
	this->inputvalue_functionmap["Upgrade-Insecure-Requests"] = this->set_upgrade_insecure_requests;
	this->inputvalue_functionmap["User-Agent"] = this->set_user_agent;
	this->inputvalue_functionmap["Vary"] = this->set_vary;
	this->inputvalue_functionmap["Via"] = this->set_via;
	this->inputvalue_functionmap["WWW-Authenticate"] = this->set_www_authenticate;
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
	this->_sec_websocket_accept = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_server(const std::string &value)
{
	this->_server = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_servertiming(const std::string &value)
{
	std::map<std::string, std::string> value_map;
	std::stringstream	ss(value);
	std::string			line;

	std::string	key;
	std::getline(ss, key, ';');
	while(std::getline(ss, line, ';'))
		value_map[HandlingString::obtain_beforeword(HandlingString::skipping_emptyword(line), '=')] = HandlingString::obtain_afterword(HandlingString::skipping_emptyword(line), '=');
	this->_servertiming.set_value(key, value_map);
}

void	HttpRequest::set_service_worker_navigation_preload(const std::string &value)
{
	this->_service_worker_navigation_preload = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_set_cookie(const std::string &value)
{
	//valueの設定の仕方が特殊なのでちょっと考えないとピケない
}

void	HttpRequest::set_sourcemap(const std::string &value)
{
	this->_sourcemap = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_strict_transport_security(const std::string &value)
{
	//valueの設定の仕方が特殊なのでちょっと考えないとピケない
}

void	HttpRequest::set_te(const std::string &value)
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
}

void	HttpRequest::set_timing_allow_origin(const std::string &value)
{
	this->_timing_allow_origin = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_trailer(const std::string &value)
{
	this->_trailer = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_transfer_encoding(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_transfer_encoding.set_value_array(value_array);
}

void	HttpRequest::set_upgrade(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_upgrade.set_value_array(value_array);
}

void	HttpRequest::set_upgrade_insecure_requests(const std::string &value)
{
	this->_upgrade_insecure_requests = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_user_agent(const std::string &value)
{
	this->_user_agent = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_vary(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_vary.set_value_array(value_array);
}

void	HttpRequest::set_via(const std::string &value)
{
	this->_via = HandlingString::skipping_emptyword(value);
}

void	HttpRequest::set_www_authenticate(const std::string &value)
{
	std::vector<std::string>	value_array;
	std::stringstream	ss(value);
	std::string			line;
	
	while(std::getline(ss, line, ','))
		value_array.push_back(HandlingString::skipping_emptyword(line));
	this->_www_authenticate.set_value_array(value_array);
}

void	HttpRequest::set_x_xss_protection(const std::string &value)
{

}