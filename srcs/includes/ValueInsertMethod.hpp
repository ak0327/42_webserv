//テンプレートを使用するため、セッターを中に入れたままだとめっちゃめんどくさくなってしまう
//セッター部分を完全に切り分けて、staticクラスとして実装したい
//要相談

#ifndef VALUEINSERTMETHOD_HPP
#define VALUEINSERTMETHOD_HPP

#include <string>
#include <iostream>

#include "ValueArraySet.hpp"
#include "ValueDateSet.hpp"
#include "ValueWeightArraySet.hpp"
#include "ValueMap.hpp"
#include "ValueInsertMethod.hpp"

class RequestLine;
class ValueWeightArraySet;
class ValueArraySet;
class ValueSet;
class TwoValueSet;
class ValueMap;
class ValueDateSet;

class ValueInsertMethod
{
	private:

	public:
		ValueWeightArraySet	ready_accept(const std::string &value);
		// void	set_accept_ch(const std::string &value);//ハイフンは_にしちゃいたいかも
		// //初期化に引数を必ず取りたいため、引数なしのコンストラクタは許可したくなく、privateに避難しているがこれだとダメっぽい？ちゃうんかい
		// void	set_accept_charset(const std::string &value);
		// void	set_accept_encoding(const std::string &value);
		// void	set_accept_language(const std::string &value);
		// //Accept-Patchどういう持ち方かわからん
		// void	set_accept_post(const std::string &value);
		// void	set_accept_ranges(const std::string &value);
		// void	set_access_control_allow_credentials(const std::string &value);
		// void	set_access_control_allow_headers(const std::string &value);
		// void	set_access_control_allow_methods(const std::string &value);
		// void	set_access_control_allow_origin(const std::string &value);
		// void	set_access_control_expose_headers(const std::string &value);
		// void	set_access_control_max_age(const std::string &value);
		// void	set_access_control_request_headers(const std::string &value);
		// void	set_access_control_request_method(const std::string &value);
		// void	set_age(const std::string &value);
		// void	set_allow(const std::string &value);
		// void	set_alt_svc(const std::string &value);
		// void	set_alt_used(const std::string &value);
		// void	set_authorization(const std::string &value);
		// //Cache-Controlどう使うのか全くわからない
		// void	set_clear_site_data(const std::string &value);
		// void	set_connection(const std::string &value);
		// void	set_content_disponesition(const std::string &value);
		// void	set_content_encoding(const std::string &value);
		// void	set_content_language(const std::string &value);
		// void	set_content_length(const std::string &value);
		// void	set_content_location(const std::string &value);
		// void	set_content_range(const std::string &value);
		// void	set_content_security_policy(const std::string &value);
		// void	set_content_security_policy_report_only(const std::string &value);
		// void	set_content_type(const std::string &value);
		// void	set_cookie(const std::string &value);
		// void	set_cross_origin_embedder_policy(const std::string &value);
		// void	set_cross_origin_opener_policy(const std::string &value);
		// void	set_cross_origin_resource_policy(const std::string &value);
		// void	set_date(const std::string &value);
		// void	set_etag(const std::string &value);
		// void	set_expect(const std::string &value);
		// //expect-ctは現状廃止されているっぽくて対応したくない
		// void	set_expires(const std::string &value);
		// void	set_forwarded(const std::string &value);
		// void	set_email(const std::string &value);
		// void	set_from(const std::string &value);
		// void	set_host(const std::string &value);
		// void	set_if_match(const std::string &value);
		// void	set_if_modified_since(const std::string &value);
		// void	set_if_none_match(const std::string &value);
		// void	set_if_range(const std::string &value);
		// void	set_if_unmodified_since(const std::string &value);
		// void	set_keepalive(const std::string &value);
		// void	set_last_modified(const std::string &value);
		// void	set_link(const std::string &value);
		// void	set_location(const std::string &value);
		// void	set_max_forwards(const std::string &value);
		// void	set_origin(const std::string &value);
		// void	set_permission_policy(const std::string &value);
		// void	set_proxy_authenticate(const std::string &value);
		// void	set_proxy_authorization(const std::string &value);
		// //range何かよくわからん
		// void	set_referer(const std::string &value);
		// void	set_referrer_policy(const std::string &value);
		// void	set_retry_after(const std::string &value);
		// void	set_sec_fetch_dest(const std::string &value);
		// void	set_sec_fetch_mode(const std::string &value);
		// void	set_sec_fetch_site(const std::string &value);
		// void	set_sec_fetch_user(const std::string &value);
		// void	set_sec_purpose(const std::string &value);
		// void	set_sec_websocket_accept(const std::string &value);
		// void	set_server(const std::string &value);
		// void	set_servertiming(const std::string &value);
		// void	set_service_worker_navigation_preload(const std::string &value);
		// void	set_set_cookie(const std::string &value);
		// void	set_sourcemap(const std::string &value);
		// void	set_strict_transport_security(const std::string &value);
		// void	set_te(const std::string &value);

		// void	set_timing_allow_origin(const std::string &value);
		// void	set_trailer(const std::string &value);
		// void	set_transfer_encoding(const std::string &value);
		// void	set_upgrade(const std::string &value);
		// void	set_upgrade_insecure_requests(const std::string &value);
		// void	set_user_agent(const std::string &value);
		// void	set_vary(const std::string &value);
		// void	set_via(const std::string &value);
		// void	set_www_authenticate(const std::string &value);
		// void	set_x_xss_protection(const std::string &value);
};

#endif