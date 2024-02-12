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

    const std::vector<ServerConfig> &get_server_configs() const;

 private:
	HttpConfig http_config_;
	Result<int, std::string> result_;
};
