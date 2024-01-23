#pragma once

# include <string>
# include <vector>
# include "AbstractSyntaxTree.hpp"
# include "Parser.hpp"
# include "Result.hpp"
# include "Tokenizer.hpp"

class Configuration {
 public:
	explicit Configuration(const std::string &file_path);
	~Configuration();

	Result<int, std::string> get_result();

 private:
	std::string conf_data_;
	std::vector<Token> tokens_;
	AbstractSyntaxTree ast_;
	Result<int, std::string> result_;

	Result<std::string, std::string> read_conf_file(const std::string &file_path);
	Result<std::vector<Token>, std::string> tokenize(const std::string &conf_data);
	Result<AbstractSyntaxTree, std::string> parse(const std::vector<Token> &tokens);
	Result<int, std::string> validate_ast(const AbstractSyntaxTree &ast);
};
