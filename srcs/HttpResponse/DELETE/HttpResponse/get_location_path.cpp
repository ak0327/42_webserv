#include <map>
#include <string>
#include "HttpResponse.hpp"
#include <iostream>

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

// http://nanka/~~
// なら~~以降が欲しい部分

void	HttpResponse::separate_path_folda_file(const std::string &request_path, std::string *search_folda, std::string *search_file)
{
	size_t	path_start_pos = 0;

	std::cout << "here" << std::endl;
	while (request_path[path_start_pos] != ':')  // skip protocol name
		path_start_pos++;
	path_start_pos = path_start_pos + 3;
	std::cout << "here" << std::endl;
	while (request_path[path_start_pos] != '/')  // skip nankaの部分　名前なんだ
		path_start_pos++;
	std::string	path = request_path.substr(path_start_pos, request_path.length() - path_start_pos);
	std::cout << "here" << std::endl;
	if (path[path.length() - 1] == '/')
	{
		*search_folda = path;
		*search_file = "";
	}
	else
	{
		size_t	last_slash_pos = path.rfind('/');
		*search_folda = path.substr(0, last_slash_pos + 1);
		*search_file = path.substr(last_slash_pos + 1, path.length() - last_slash_pos - 1);
	}
	std::cout << "here" << std::endl;
}

std::string	HttpResponse::get_location_path(const std::string &requested_path)
{
	std::string	search_folda;
	std::string	search_file;

	// requestでくるpathを受け取る
	// 探すものがディレクティブかファイルかどうかを判定、どっかに持っておく
	separate_path_folda_file(requested_path, &search_folda, &search_file);
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
