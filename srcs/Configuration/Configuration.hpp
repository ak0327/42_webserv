#pragma once

# include <deque>
# include <map>
# include <string>
# include <vector>
# include "Parser.hpp"
# include "Result.hpp"
# include "Token.hpp"
# include "Tokenizer.hpp"

class Configuration {
 public:
	explicit Configuration(const char *file_path);
	Configuration(const Configuration &other);
	~Configuration();

	Configuration &operator=(const Configuration &rhs);

	Result<int, std::string> get_result();
    const std::map<ServerInfo, const ServerConfig *> &get_server_configs() const;
    const ServerConfig &get_server_config(const ServerInfo &server_info) const;

 private:
	HttpConfig http_config_;
    std::map<ServerInfo, const ServerConfig *> server_configs_;
    std::map<AddressPortPair, const ServerConfig *> default_servers_;

    Result<int, std::string> result_;

    Result<int, std::string> set_default_servers();
    Result<int, std::string> set_default_server_to_default_listen();
    void set_default_server_to_first_listen();
    void set_server_configs();
    const ServerConfig &get_default_server(const AddressPortPair &pair) const;
};


std::ostream &operator<<(std::ostream &out, const std::map<AddressPortPair, const ServerConfig *> &default_servers);
std::ostream &operator<<(std::ostream &out, const AddressPortPair &pair);
