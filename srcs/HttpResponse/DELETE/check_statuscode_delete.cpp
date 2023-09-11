//100statuscode

#include "testclasss.hpp"
#include <string>
#include <vector>

ServerConfig test;

USER_ID = "test"
USER_PASS = "testpass"

int check_statuscode_delete(const std::string &subject_source)//リクエストクラスが入ってくる感じになっているはず、なので構成が違う
{
	//クラスを渡すと大きくなってしまうため、文字列型として渡す
	std::vector<std::string> must_request_header;
	must_request_header.push_back("Host");//クラスの中に本来格納されている情報
	std::vector<std::string>::iterator key_it = must_request_header.begin();
	while (key_it != must_request_header.end())
	{
		if (test.get_serverconfig_value().check_configset_key() == false)
			return (400);
		key_it++;
	}

	//ユーザー認証情報に関してどこに保存するか分からないので、マクロで設定する
	//が資格情報をどう合わせるかがわからず、頓挫

	if ()
}