#pragma once

# include <deque>
# include <string>
# include <vector>
# include "AbstractSyntaxTree.hpp"
# include "Token.hpp"
# include "Result.hpp"

struct LocationConfig {
	std::string path;
	std::string root;
};

struct ServerConfig {
	std::string listen;
	std::string server_name;
	std::vector<LocationConfig> locations;
};

struct HttpConfig {
	std::vector<ServerConfig> servers;
};

class Parser {
 public:
	Parser();
	explicit Parser(const char *file_path);
	Parser(const Parser &other);
	~Parser();

	Parser &operator=(const Parser &rhs);

	Result<int, std::string> get_result() const;
	HttpConfig get_config() const;

 private:
	HttpConfig http_config_;
	Result<int, std::string> result_;

	static Result<std::string, std::string> get_configration_file_contents(const char *file_path);
	static Result<std::deque<Token>, std::string> tokenize(const std::string &conf_data);
	static Result<AbstractSyntaxTree, std::string> parse(const std::deque<Token> &tokens);
	static Result<int, std::string> validate_ast(const AbstractSyntaxTree &ast);
};
