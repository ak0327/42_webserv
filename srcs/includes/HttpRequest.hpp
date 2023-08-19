#ifndef HTTPREQUEST_HPP
#define HTTPREQUEST_HPP

#include <map>
#include <string>
#include <vector>
#include <sstream>
#include <set>

#include "HandlingString.hpp"
#include "ValueWeightArraySet.hpp"
#include "ValueArraySet.hpp"
#include "ValueSet.hpp"

class ValueWeightArraySet;
class ValueArraySet;
class ValueSet;

class HttpRequest
{
	private:
		ValueWeightArraySet	_accept;//命名規則はMDN上に乗っている名前の前に_をつけることで対応していく、ただし大文字は全て小文字に変更して対応するものとする//要相談
		ValueArraySet		_accept_ch;//ハイフンは_にしちゃいたいかも
		//初期化に引数を必ず取りたいため、引数なしのコンストラクタは許可したくなく、privateに避難しているがこれだとダメっぽい？ちゃうんかい
		ValueArraySet		_accept_charset;
		ValueWeightArraySet	_accept_encoding;
		ValueWeightArraySet	_accept_language;
		//Accept-Patchどういう持ち方かわからん
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
		//Alt-Svc値どう使うのか全くわからない
		ValueArraySet		_authorization;
		//Cache-Controlどう使うのか全くわからない
		ValueArraySet		_clear_site_data;
		//connectionは危険っぽいので無視していいっすか？
		//content_disponesitionは特殊なクラスを与えた方が良さそう
		ValueArraySet		_content_encoding;
		ValueArraySet		_content_language;
		ValueSet			_content_length;
		ValueSet			_content_location;
		//content-rangeは特殊なクラスを与えた方が良さそう
		//content-security-policyよくわからん
		//content-security-policy-report-onlyよくわからん
		//content-typeは特殊なクラスを与えた方が良さそう
		//cookieは特殊なクラスを与えた方が良さそう
		ValueSet			_cross_origin_embedder_policy;
		ValueSet			_cross_origin_opener_policy;
		//Cross-Origin=Resource-Policyはバグあるっぽくて対応したくない
		ValueSet			_date;
		ValueSet			_etag;
		ValueSet			_expect;
		//expect-ctは現状廃止されているっぽくて対応したくない
		ValueSet			_expires;
		//Forwardedは特殊なクラスを与えた方がいいかも
		ValueSet			_email;
		//Hostは特殊なクラスを与えた方がいいかも
		ValueArraySet		_if_match;
		ValueSet			_if_modified_since;
		ValueArraySet		_if_none_match;
		ValueSet			_if_range;
		ValueSet			_if_unmodified_since;
		//keepaliveは危険らしく対応したくない
		ValueSet			_last_modified;
		//Linkは特殊なクラスを持たせたほうがいいかも
		ValueSet			_location;
		//Originは特殊なクラスを持たせたほうがいいかも
		//permission-policy何してるのかよくわからん
		//proxy-authenticateは特殊なクラスを持たせたほうがいいかも
		//proxy-authorizationは特殊なクラスを持たせたほうがいいかも
		//range何かよくわからん
		//refererに関しては危険っぽいので対応したくない
		ValueSet			_referrer_policy;
		ValueSet			_retry_after;
		ValueSet			_server;
		//servertimingよくわからん
		//set-cookieよくわからん　そもそもcookieってなんだよお菓子かよ
		ValueSet			_sourcemap;
		ValueSet			_timing_allow_origin;
		ValueSet			_transfer_encoding;
		//upgradeも対応したくない
		ValueSet			_upgrade_insecure_requests;
		//User-Agentは特殊なクラスを持たせたほうがいいかも
		ValueArraySet		_vary;
		//Viaは特殊なクラスを持たせたほうがいいかも
		ValueArraySet		_www_authenticate;
		ValueSet			_x_content_type_options;
		ValueSet			_x_frame_options;
		//x-xss-protectionはなんか特殊な機能っぽいので不対応でいきたい
		
	
	public:
		HttpRequest();
		HttpRequest(const std::string&);
		~HttpRequest();
		HttpRequest(const HttpRequest &other);
		HttpRequest &operator=(const HttpRequest &other);

		//debug関数
		void show_requestinfs(void);
};

#endif