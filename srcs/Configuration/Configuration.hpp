#pragma once

# include <deque>
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

 private:
	HttpConfig http_config_;
    std::map<ServerInfo, const ServerConfig *> server_configs_;

    Result<int, std::string> result_;

    void set_server_configs();
};
