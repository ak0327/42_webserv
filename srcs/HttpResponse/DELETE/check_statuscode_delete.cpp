//100statuscode
#include <string>
#include <iostream>
#include <map>


std::map<std::string, std::string> key_set;
key_set["Upgrade"] = "websocket";//リクエストの塊みたいな感じ

class ConfigSet
{
	private:
		std::map<std::string, std::string> config_set;
	public:
		ConfigSet(){}
		~ConfigSet(){}

		void set_configset(){
			this->config_set["Upgrade"] = "~~~";//ここに"test"ロケーションの設定を記載していく
		}

		void get_configset_value(const std::string &key){
			return (this->config_set[key]);
		}

		bool check_configset_key(const std::string &key){
			if (this->config_set.find(key) == config_set.end())
				return (false);
			else
				return (true);
		}
};

class ServerConfig
{
	private:
		std::map<std::string, ConfigSet> all_config_set;
	public:
		ServerConfig(){
			all_config_set["test"] = ConfigSet();//もし他のロケーションを作りたければここに追加
			all_config_set["test"].set_configset();
		};
		~ServerConfig(){};

		get_serverconfig_value(const std::string &subject_url){
			return (this->all_config_set[subject_url]);
		};

		bool check_serverconfig_key(const std::string &key){
			if (this->all_config_set.find(key) == all_config_set.end())
				return (false);
			else
				return (true);
		}
};

ServerConfig test;

int	return_101(const std::string &subject_url)
{ 
	if (key_set.find("Upgrade") != key_set.end())//requestの中になければ
	{
		if (test.check_serverconfig_key(subject_url) == true)//locationの中身を確認して、proxy_passというキーが存在しているか確認して
		{

		}
		else//対象のurlが見つからない場合
		{
			return (404);//つまりnot found
		}
	}
}