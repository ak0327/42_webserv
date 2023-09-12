#ifndef SRCS_HTTPREQUEST_HTTPREQUEST_HTTPREQUEST_HPP_
#define SRCS_HTTPREQUEST_HTTPREQUEST_HTTPREQUEST_HPP_

#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <set>

#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"
#include "../HandlingString/HandlingString.hpp"
#include "../RequestLine/RequestLine.hpp"
#include "../ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../ValueArraySet/ValueArraySet.hpp"
#include "../ValueSet/ValueSet.hpp"
#include "../TwoValueSet/TwoValueSet.hpp"
#include "../ValueMap/ValueMap.hpp"
#include "../ValueDateSet/ValueDateSet.hpp"

class BaseKeyValueMap;

class RequestLine;
class ValueWeightArraySet;
class ValueArraySet;
class ValueSet;
class TwoValueSet;
class ValueMap;
class ValueDateSet;

class HttpRequest
{
	private:
		RequestLine	_requestline;
		std::map<std::string, void(HttpRequest::*)(const std::string&, const std::string&)> inputvalue_functionmap;
		std::map<std::string, BaseKeyValueMap*> request_keyvalue_map;
		HttpRequest();
		HttpRequest(const HttpRequest &other);
		bool		check_keyword_exist(const std::string &key);
		std::string	obtain_request_key(const std::string value);
		std::string	obtain_request_value(const std::string value);
		TwoValueSet			*ready_TwoValueSet(const std::string &value);
		TwoValueSet			*ready_TwoValueSet(const std::string &value, char delimiter);
		ValueArraySet		*ready_ValueArraySet(const std::string &value);
		ValueDateSet		*ready_ValueDateSet(const std::string &value);
		ValueMap			*ready_ValueMap(const std::string &value);
		ValueMap			*ready_ValueMap(const std::string &only_value, const std::string &value);
		ValueSet			*ready_ValueSet(const std::string &value);
		ValueWeightArraySet	*ready_ValueWeightArraySet(const std::string &value);
		void				ready_functionmap(void);
		double				_status_code;
	public:
		explicit HttpRequest(const std::string &all_request_text);
		~HttpRequest();
		// void	set_all_method();
		void	set_accept(const std::string &key, const std::string &value);
		void	set_accept_ch(const std::string &key, const std::string &value);
		void	set_accept_charset(const std::string &key, const std::string &value);
		void	set_accept_encoding(const std::string &key, const std::string &value);
		void	set_accept_language(const std::string &key, const std::string &value);
		bool	check_accept_langage_valueword(const std::string &value);
		// void	set_//方かわからん
		void	set_accept_post(const std::string &key, const std::string &value);
		void	set_accept_ranges(const std::string &key, const std::string &value);
		void	set_access_control_allow_credentials(const std::string &key, const std::string &value);
		void	set_access_control_allow_headers(const std::string &key, const std::string &value);
		void	set_access_control_allow_methods(const std::string &key, const std::string &value);
		void	set_access_control_allow_origin(const std::string &key, const std::string &value);
		void	set_access_control_expose_headers(const std::string &key, const std::string &value);
		void	set_access_control_max_age(const std::string &key, const std::string &value);
		void	set_access_control_request_headers(const std::string &key, const std::string &value);
		void	set_access_control_request_method(const std::string &key, const std::string &value);
		void	set_age(const std::string &key, const std::string &value);
		void	set_allow(const std::string &key, const std::string &value);
		void	set_alt_svc(const std::string &key, const std::string &value);
		void	set_alt_used(const std::string &key, const std::string &value);
		void	set_authorization(const std::string &key, const std::string &value);
		// void	set//か全くわからない うまく分けられん
		void	set_clear_site_data(const std::string &key, const std::string &value);
		void	set_connection(const std::string &key, const std::string &value);
		void	set_content_disponesition(const std::string &key, const std::string &value);
		void	set_content_encoding(const std::string &key, const std::string &value);
		void	set_content_language(const std::string &key, const std::string &value);
		void	set_content_length(const std::string &key, const std::string &value);
		void	set_content_location(const std::string &key, const std::string &value);
		void	set_content_range(const std::string &key, const std::string &value);
		void	set_content_security_policy(const std::string &key, const std::string &value);
		void	set_content_security_policy_report_only(const std::string &key, const std::string &value);
		void	set_content_type(const std::string &key, const std::string &value);
		void	set_cookie(const std::string &key, const std::string &value);
		void	set_cross_origin_embedder_policy(const std::string &key, const std::string &value);
		void	set_cross_origin_opener_policy(const std::string &key, const std::string &value);
		void	set_cross_origin_resource_policy(const std::string &key, const std::string &value);
		void	set_date(const std::string &key, const std::string &value);
		void	set_etag(const std::string &key, const std::string &value);
		void	set_expect(const std::string &key, const std::string &value);
		// void	set//ているっぽくて対応したくない
		void	set_expires(const std::string &key, const std::string &value);
		void	set_forwarded(const std::string &key, const std::string &value);
		void	set_email(const std::string &key, const std::string &value);
		void	set_from(const std::string &key, const std::string &value);
		void	set_host(const std::string &key, const std::string &value);
		void	set_if_match(const std::string &key, const std::string &value);
		void	set_if_modified_since(const std::string &key, const std::string &value);
		void	set_if_none_match(const std::string &key, const std::string &value);
		void	set_if_range(const std::string &key, const std::string &value);
		void	set_if_unmodified_since(const std::string &key, const std::string &value);
		void	set_keep_alive(const std::string &key, const std::string &value);
		void	set_last_modified(const std::string &key, const std::string &value);
		void	set_link(const std::string &key, const std::string &value);
		void	set_location(const std::string &key, const std::string &value);
		void	set_max_forwards(const std::string &key, const std::string &value);
		void	set_origin(const std::string &key, const std::string &value);
		void	set_permission_policy(const std::string &key, const std::string &value);
		void	set_proxy_authenticate(const std::string &key, const std::string &value);
		void	set_proxy_authorization(const std::string &key, const std::string &value);
		// void	set//れどれが当てはまるかわからん
		void	set_referer(const std::string &key, const std::string &value);
		void	set_referrer_policy(const std::string &key, const std::string &value);
		void	set_retry_after(const std::string &key, const std::string &value);
		void	set_sec_fetch_dest(const std::string &key, const std::string &value);
		void	set_sec_fetch_mode(const std::string &key, const std::string &value);
		void	set_sec_fetch_site(const std::string &key, const std::string &value);
		void	set_sec_fetch_user(const std::string &key, const std::string &value);
		void	set_sec_purpose(const std::string &key, const std::string &value);
		void	set_sec_websocket_accept(const std::string &key, const std::string &value);
		void	set_server(const std::string &key, const std::string &value);
		void	set_servertiming(const std::string &key, const std::string &value);
		void	set_service_worker_navigation_preload(const std::string &key, const std::string &value);
		void	set_set_cookie(const std::string &key, const std::string &value);
		void	set_sourcemap(const std::string &key, const std::string &value);
		void	set_strict_transport_security(const std::string &key, const std::string &value);
		void	set_te(const std::string &key, const std::string &value);
		void	set_timing_allow_origin(const std::string &key, const std::string &value);
		void	set_trailer(const std::string &key, const std::string &value);
		void	set_transfer_encoding(const std::string &key, const std::string &value);
		void	set_upgrade(const std::string &key, const std::string &value);
		void	set_upgrade_insecure_requests(const std::string &key, const std::string &value);
		void	set_user_agent(const std::string &key, const std::string &value);
		void	set_vary(const std::string &key, const std::string &value);
		void	set_via(const std::string &key, const std::string &value);
		void	set_www_authenticate(const std::string &key, const std::string &value);
		void	set_x_xss_protection(const std::string &key, const std::string &value);
		// debug関数
		void show_requestinfs(void);
};

#endif  // SRCS_HTTPREQUEST_HTTPREQUEST_HTTPREQUEST_HPP_
