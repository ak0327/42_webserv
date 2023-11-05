#include "DeleteHttpResponse.hpp"

// reserved    = gen-delims / sub-delims
//     gen-delims  = ":" / "/" / "?" / "#" / "[" / "]" / "@"
//     sub-delims  = "!" / "$" / "&" / "'" / "(" / ")"
//                   "*" / "+" / "," / ";" / "="


// 許可されているformは下記の四種類
// 1 origin-form 2 absolute-form 3 authority-form 4 asterisk-form
// いかにそれぞれのFMTを記載していく
//
// 1 origin-form
// origin-form = absolute-path [ "?" query ]
//     absolute-path = 1*( "/" segment )
// 2absolute-form
// absolute-form = absolute-URI
//    absolute-URI = <absolute-URI, [URI] > ; 絶対 URI
//        absolute-URI  = scheme ":" hier-part [ "?" query ]
//            scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
//            hier-part   = "//" authority path-abempty
//                          path-absolute
//                          path-rootless
//                          path-empty
//                authority = [ userinfo "@" ] host [ ":" port ]
//                    userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
//                    pct-encoded = "%" HEXDIG HEXDIG
//                    host = IP-literal / IPv4address / reg-name
//                        IP-literal = "[" ( IPv6address / IPvFuture  ) "]"
//                            IPv6address = 6( h16 ":" ) ls32
//                                          "::" 5( h16 ":" ) ls32
//                                         [ h16 ] "::" 4( h16 ":" ) ls32
//                                         [ *1( h16 ":" ) h16 ] "::" 3( h16 ":" ) ls32
//                                         [ *2( h16 ":" ) h16 ] "::" 2( h16 ":" ) ls32
//                                         [ *3( h16 ":" ) h16 ] "::" h16 ":"   ls32
//                                         [ *4( h16 ":" ) h16 ] "::" ls32
//                                         [ *5( h16 ":" ) h16 ] "::" h16
//                                         [ *6( h16 ":" ) h16 ] "::"
//                                ls32 = ( h16 ":" h16 ) / IPv4address
//                                ; アドレスの下位 32 ビット
//                                h16 = 1*4HEXDIG
//                                ; 16 進数字で表現される 16 ビットのアドレス
//                            IPvFuture = "v" 1*HEXDIG "." 1*( unreserved / sub-delims / ":" )
//                            IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
//                                dec-octet = DIGIT ; 0-9
//                                            %x31-39 DIGIT ; 10-99
//                                            "1" 2DIGIT ; 100-199
//                                            "2" %x30-34 DIGIT ; 200-249
//                                            "25" %x30-35 ; 250-255
//                            reg-name = *( unreserved / pct-encoded / sub-delims )
//                    port = *DIGIT
//                path-abempty = *( "/" segment )
//                    segment = *pchar
//                        pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
//                path-absolute = "/" [ segment-nz *( "/" segment ) ]
//                    segment-nz = 1*pchar
//                path-rootless = segment-nz *( "/" segment )
//                path-noscheme = segment-nz-nc *( "/" segment )
//                    segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
//                path-empty = 0<pchar>
// 3authority-form
// authority-form = uri-host ":" port
//     uri-host = IP-literal / IPv4address / reg-name
//     port = *DIGIT
// 4 asterisk-form
// asterisk-form = "*"
// namespace Config
// {
// 	std::string	alias;
// 	std::string	root;
// 	std::string	index;
// 	std::map<std::string, std::string>	location_map;

// 	std::string	no_path = "no_path";
// 	std::string path = "/";
// 	location_map[path] = "root";
// 	path = "/www";
// 	location_map[path] = "root_www";
// 	path = "/www/src";
// 	location_map[path] = "root_www_src";
// 	path = "/www/src/html";
// 	location_map[path] = "root_www_src_html";
// 	path = "/www/src/css";
// 	location_map[path] = "root_www_src_html";
// }  // namespace Config

// requestでくるpathを受け取る
	// まずaliasが設定されているかを確認する
		// -- 設定されていればパスの塗り替え
		// (aliasがない場合)次にrootが設定されているかを確認する
			// -- 設定されていればパスの塗り替え
				// aliasもindexもない場合そのままパスを受け取る

// pattern 1
// 何かしらのURLが送られてくる /hoge
// ? /配下のhoogeかもしれないし　/hoge というフォルダをしている可能性
// 		-- 末尾にスラッシュがなければファイルとして探し、そうでなければフォルダを探す　ほんまか？
std::string	make_target_path(const std::string &path)
{
	// if (Config::alias != "")
	// {
	// 	// aliasをくっつけるような処理？
	// 	return (path);
	// }
	// if (Config::root != "")
	// {
	// 	// aliasをくっつけるような処理？
	// 	return (path);
	// }
	return (path);
}

std::string	DeleteHttpResponse::skip_authority(const std::string &target_path)
{
	size_t	path_start_pos = 3;

	while (target_path[path_start_pos] != '/')
		path_start_pos++;
	return (target_path.substr(path_start_pos));
}

bool	DeleteHttpResponse::is_authority(const std::string &request_path)
{
	return (request_path[0] == '/' && request_path[1] == '/');
}

std::string	DeleteHttpResponse::trim_scheme_and_query(const std::string &target_uri)
{
	size_t	path_start_pos = 0;
	size_t	path_end_pos = target_uri.length();

	while (target_uri[path_start_pos] != ':')
		path_start_pos++;
	path_start_pos++;
	if (std::count(target_uri.begin(), target_uri.end(), '?') != 0)
	{
		while (target_uri[path_end_pos] != '?')
			path_end_pos--;
		path_end_pos--;
	}
	return (target_uri.substr(path_start_pos, path_end_pos));
}

std::string	DeleteHttpResponse::trim_query(const std::string &target_uri)
{
	if (std::count(target_uri.begin(), target_uri.end(), '?') == 0)
		return (target_uri);
	size_t	query_pos = target_uri.length();
	while (target_uri[query_pos] != '?')
		query_pos = query_pos - 1;
	query_pos--;
	return (target_uri.substr(query_pos));
}

bool	DeleteHttpResponse::is_asterisk_form(const std::string &target_uri)
{
	return (target_uri == "*");
}

bool	DeleteHttpResponse::is_authority_form(const std::string &target_uri)
{
	size_t	pos = 0;

	if (std::count(target_uri.begin(), target_uri.end(), ':') == 0)
		return (false);
	while (target_uri[pos] != ':')
		pos++;
	pos++;
	while (target_uri[pos] != '\0')
	{
		if (isdigit(target_uri[pos]) == false)
			return (false);
		pos++;
	}
	return (true);
}

bool	DeleteHttpResponse::is_origin_form(const std::string &target_uri)
{
	return (target_uri[0] == '/');
}

std::string	DeleteHttpResponse::get_location_from_requestline_targeturi(const std::string &target_uri)
{
	if (is_origin_form(target_uri))
		return (trim_query(target_uri));
	if (is_authority_form(target_uri) || is_asterisk_form(target_uri))
		return "";
	std::string hier_part = trim_scheme_and_query(target_uri);
	if (is_authority(hier_part))
	{
		std::string path_abempty = skip_authority(hier_part);
		return (trim_query(path_abempty));
	}
	return (trim_query(hier_part));
}

std::string	DeleteHttpResponse::get_location_path(const std::string &requested_path)
{
	// この先の処理を書くのにまだメモ書き消さないで欲しいです
	// request lineでくるpathを受け取り、locationを切り出す
	std::string location_path =  get_location_from_requestline_targeturi(requested_path);
	// まずaliasが設定されているかを確認する
		// -- 設定されていればパスの塗り替え
		// (aliasがない場合)次にrootが設定されているかを確認する
			// -- 設定されていればパスの塗り替え
				// aliasもindexもない場合そのままパスを受け取る
	std::string	target_path = make_target_path(requested_path);
	// ここまででpathが完成する
	// locationの中に該当のパスがあるかどうか
		// -- パスがあればそのConfigを取得する
		// -- パスがない場合はserverに元から書いているものを参照する（無かったら？
	// if (is_exist_path())
	return "";
}
