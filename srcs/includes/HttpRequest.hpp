#ifndef HTTPREQUEST_HPP
#define HTTPREQUEST_HPP

#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <set>

#include "HandlingString.hpp"
#include "RequestLine.hpp"
#include "ValueWeightArraySet.hpp"
#include "ValueArraySet.hpp"
#include "ValueSet.hpp"
#include "TwoValueSet.hpp"
#include "ValueMap.hpp"

class RequestLine;
class ValueWeightArraySet;
class ValueArraySet;
class ValueSet;
class TwoValueSet;
class ValueMap;

//日付に関するクラスを作成すること

class HttpRequest
{
	private:
		RequestLine			_requestline;

		ValueWeightArraySet	_accept;
		ValueArraySet		_accept_ch;
		ValueArraySet		_accept_charset;
		ValueWeightArraySet	_accept_encoding;
		ValueWeightArraySet	_accept_language;
		//Accept-Patchどういう持ち方かわからん
		TwoValueSet			_accept_post;
		ValueSet			_accept_ranges;
		ValueSet			_access_control_allow_credentials;
		ValueArraySet		_access_control_allow_headers;
		ValueArraySet		_access_control_allow_methods;
		ValueSet			_access_control_allow_origin;
		ValueArraySet		_access_control_expose_headers;
		ValueSet			_access_control_max_age;
		ValueArraySet		_access_control_request_headers;
		ValueSet			_access_control_request_method;
		ValueSet			_age;
		ValueArraySet		_allow;
		ValueMap			_alt_svc;
		TwoValueSet			_alt_used;
		ValueArraySet		_authorization;
		//Cache-Controlどう使うのか全くわからない うまく分けられん
		ValueArraySet		_clear_site_data;
		ValueSet			_connection;
		ValueMap			_content_disponesition;
		ValueArraySet		_content_encoding;
		ValueArraySet		_content_language;
		ValueSet			_content_length;
		ValueSet			_content_location;
		ValueSet			_content_range;
		TwoValueSet			_content_security_policy;
		TwoValueSet			_content_security_policy_report_only;
		ValueMap			_content_type;
		ValueMap			_cookie;
		ValueSet			_cross_origin_embedder_policy;
		ValueSet			_cross_origin_opener_policy;
		ValueSet			_cross_origin_resource_policy;
		ValueSet			_date;
		ValueSet			_etag;
		ValueSet			_expect;
		//expect-ctは現状廃止されているっぽくて対応したくない
		ValueSet			_expires;
		ValueMap			_forwarded;
		ValueSet			_email;
		ValuseSet			_from;
		TwoValueSet			_host;
		ValueArraySet		_if_match;
		ValueSet			_if_modified_since;
		ValueArraySet		_if_none_match;
		ValueSet			_if_range;
		ValueSet			_if_unmodified_since;
		ValueSet			_keep_alive;
		ValueSet			_last_modified;
		ValueMap			_link;
		ValueSet			_location;
		ValueSet			_max_forwards;
		ValueSet			_origin;
		TwoValueSet			_permission_policy;
		ValueMap			_proxy_authenticate;
		TwoValueSet			_proxy_authorization;
		//range何かよくわからん これどれが当てはまるかわからん
		ValueSet			_referer;
		ValueSet			_referrer_policy;
		ValueSet			_retry_after;
		ValueSet			_sec_fetch_dest;
		ValueSet			_sec_fetch_mode;
		ValueSet			_sec_fetch_site;
		ValueSet			_sec_fetch_user;
		ValueSet			_sec_purpose;
		ValueSet			_sec_websocket_accept;
		ValueSet			_server;
		ValueMap			_servertiming;
		ValueSet			_service_worker_navigation_preload;
		ValueMap			_set_cookie;
		ValueSet			_sourcemap;
		ValueMap			_strict_transport_security;
		ValueSet			_te;
		ValueSet			_timing_allow_origin;
		ValueSet			_trailer;
		ValueSet			_transfer_encoding;
		ValueArraySet		_upgrade;
		ValueSet			_upgrade_insecure_requests;
		ValueSet			_user_agent;
		ValueArraySet		_vary;
		ValueSet			_via;
		ValueArraySet		_www_authenticate;
		ValueMap			_x_xss_protection;

		HttpRequest();
		HttpRequest(const HttpRequest &other);
		HttpRequest &operator=(const HttpRequest &other);

		bool		check_keyword_exist(const std::string &key);
		std::string	obtain_request_key(const std::string value);
		std::string	obtain_request_value(const std::string value);
	
	public:
		HttpRequest(const std::string &value);
		~HttpRequest();

		void	set_accept(const std::string &value);//命名規則はMDN上に乗っている名前の前に_をつけることで対応していく、ただし大文字は全て小文字に変更して対応するものとする//要相談
		void	set_accept_ch(const std::string &value);//ハイフンは_にしちゃいたいかも
		//初期化に引数を必ず取りたいため、引数なしのコンストラクタは許可したくなく、privateに避難しているがこれだとダメっぽい？ちゃうんかい
		void	set_accept_charset(const std::string &value);
		void	set_accept_encoding(const std::string &value);
		void	set_accept_language(const std::string &value);
		//Accept-Patchどういう持ち方かわからん
		void	set_accept_ranges(const std::string &value);
		void	set_access_control_allow_credentials(const std::string &value);
		void	set_access_control_allow_headers(const std::string &value);
		void	set_access_control_allow_methods(const std::string &value);
		void	set_access_control_allow_origin(const std::string &value);
		void	set_access_control_expose_headers(const std::string &value);
		void	set_access_control_max_age(const std::string &value);
		void	set_access_control_request_headers(const std::string &value);
		void	set_access_control_request_method(const std::string &value);
		void	set_age(const std::string &value);
		void	set_allow(const sts::string &value);
		//Alt-Svc値どう使うのか全くわからない
		void	set_authorization(const std::string &value);
		//Cache-Controlどう使うのか全くわからない
		void	set_clear_site_data(const std::string &value);
		//connectionは危険っぽいので無視していいっすか？
		//content_disponesitionは特殊なクラスを与えた方が良さそう
		void	set_content_encoding(const std::string &value);
		void	set_content_language(const std::string &value);
		void	set_content_length(const std::string &value);
		void	set_content_location(const std::string &value);
		//content-rangeは特殊なクラスを与えた方が良さそう
		//content-security-policyよくわからん
		//content-security-policy-report-onlyよくわからん
		//content-typeは特殊なクラスを与えた方が良さそう
		//cookieは特殊なクラスを与えた方が良さそう
		void	set_cross_origin_embedder_policy(const std::string &value);
		void	set_cross_origin_opener_policy(const std::string &value);
		//Cross-Origin=Resource-Policyはバグあるっぽくて対応したくない
		void	set_date(const std:string &value);
		void	set_etag(const std::string &value);
		void	set_expect(const std::string &value);
		//expect-ctは現状廃止されているっぽくて対応したくない
		void	set_expires(const std::string &value);
		//Forwardedは特殊なクラスを与えた方がいいかも
		void	set_email(const std::string &value);
		//Hostは特殊なクラスを与えた方がいいかも
		void	set_if_match(const std::string &value);
		void	set_if_modified_since(const std::string &value);
		void	set_if_none_match(const std::string &value);
		void	set_if_range(const std::string &value);
		void	set_if_unmodified_since(const std::string &value);
		//keepaliveは危険らしく対応したくない
		void	set_last_modified(const std::string &value);
		//Linkは特殊なクラスを持たせたほうがいいかも
		void	set_location(const std::string &value);
		//Originは特殊なクラスを持たせたほうがいいかも
		//permission-policy何してるのかよくわからん
		//proxy-authenticateは特殊なクラスを持たせたほうがいいかも
		//proxy-authorizationは特殊なクラスを持たせたほうがいいかも
		//range何かよくわからん
		//refererに関しては危険っぽいので対応したくない
		void	set_referrer_policy(const std::string &value);
		void	set_retry_after(const std::string &value);
		void	set_server(const std::string &value);
		//servertimingよくわからん
		//set-cookieよくわからん　そもそもcookieってなんだよお菓子かよ
		void	set_sourcemap(const std::string &value);
		void	set_timing_allow_origin(const std::string &value);
		void	set_transfer_encoding(const std::string &value);
		//upgradeも対応したくない
		void	set_upgrade_insecure_requests(const std::string &value);
		//User-Agentは特殊なクラスを持たせたほうがいいかも
		void	set_vary(const std::string &value);
		//Viaは特殊なクラスを持たせたほうがいいかも
		void	set_www_authenticate(const std::string &value);
		void	set_x_content_type_options(const std::string &value);
		void	set_x_frame_options(const std::string &value);

		//debug関数
		void show_requestinfs(void);
};

#endif