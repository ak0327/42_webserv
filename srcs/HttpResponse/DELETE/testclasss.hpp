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
			this->config_set["Host"] = "aaa";
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

		std::map<std::string, ConfigSet> get_serverconfig_value(const std::string &subject_url){
			return (this->all_config_set[subject_url]);
		};

		bool check_serverconfig_key(const std::string &key){
			if (this->all_config_set.find(key) == all_config_set.end())
				return (false);
			else
				return (true);
		}
};
