#pragma once

#include <vector>
#include <string>
#include <iostream>

#include "../HandleString/ConfigHandlingString.hpp"

class ErrorPage
{
 private:
		std::vector<std::string>	changed_statuscode;
		std::string					tgt_statuscode;
		std::string					redirect_path;

 public:
		ErrorPage();
		~ErrorPage();
		ErrorPage(ErrorPage const &other);
        ErrorPage &operator=(ErrorPage const &other);
		ErrorPage &operator=(ErrorPage &other);

		void						set_changed_stutsucode(std::vector<std::string> const &status_code_set);
		void						set_target_statuscode(std::string const &target_statuscode);
		void						set_redirect_path(std::string const &redirect_path);

		std::vector<std::string>	get_changed_stutsucode() const;
		std::string					get_target_statuscode() const;
		std::string					get_redirect_path() const;

		void						show_wrrorpage_infos();
};

// 　　　　　　　　　　　　　　　　　 　　　　　_
// 　　　　　　　　　　　　　　　　　　　　　／ ）
// 　　　　　　　　　 　 　 　 　 　　　　/　/　＿
// 　　　　　　　　　　　　　　_....,,,,/, /,ィく　ｽ
// 　　　　　　 　 　　　　,　'´　　　　 ｀`<´｀'' ´　ﾎﾞｸﾄｹｲﾔｸｼﾃｶﾞﾝﾀﾞﾑﾉ
// 　　　　　　　_...,,,,__　/　　　　　　　　＼　　　ﾊﾟｲﾛｯﾄﾆﾅｯﾃﾖ！
// 　　　　　　く＿__,,..7ー､　　　　　。　　　　ﾊ
// 　　　　　　_,.ｒ､ｊFﾖ__!　　　。　,. -‐''´　!
// 　　　　　　（　　}ｲコｆﾞl 　 　 ／　　　　　　!
// 　　　　　　　　－'　ヾグ　　, '　　　　　　　/
// 　　　 　 　 　　　　　 ＼ ／　　　　　 　／
// 　　　　　　　　　　 　　　｀'' －―‐ ''´
