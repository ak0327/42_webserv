#pragma once

# include <deque>
# include <string>
# include "AbstractSyntaxTree.hpp"
# include "Parser.hpp"
# include "Result.hpp"
# include "Tokenizer.hpp"

class Configuration {
 public:
	explicit Configuration(const char *file_path);
	Configuration(const Configuration &other);
	~Configuration();
	Configuration &operator=(const Configuration &rhs);

	Result<int, std::string> get_result();

	// -- tmp: 既存のテスト用 --
	Configuration() : ip_("127.0.0.1"), port_("8080") {}
	void set_ip(const std::string &ip) { ip_ = ip; }
	void set_port(const std::string &port) { port_ = port; }
	std::string get_server_ip() const { return ip_; }
	std::string get_server_port() const { return port_; }
	// ------------------------

 private:
	std::string conf_data_;
	std::deque<Token> tokens_;
	AbstractSyntaxTree ast_;
	Result<int, std::string> result_;

	Result<std::string, std::string> read_conf_file(const std::string &file_path);
	Result<std::vector<Token>, std::string> tokenize(const std::string &conf_data);
	Result<AbstractSyntaxTree, std::string> parse(const std::vector<Token> &tokens);
	Result<int, std::string> validate_ast(const AbstractSyntaxTree &ast);
	// -- tmp: 既存のテスト用 --
	std::string ip_;
	std::string port_;
	// ------------------------

	static Result<std::string, std::string> get_configration_file_contents(const char *file_path);
	static Result<std::deque<Token>, std::string> tokenize(const std::string &conf_data);
	static Result<AbstractSyntaxTree, std::string> parse(const std::deque<Token> &tokens);
	static Result<int, std::string> validate_ast(const AbstractSyntaxTree &ast);
};
