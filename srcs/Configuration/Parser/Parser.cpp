#include <deque>
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Parser.hpp"


Parser::Parser() {}


Parser::Parser(const char *file_path) {
	Result<std::string, std::string> read_result;
	Result<std::deque<Token>, std::string> tokenize_result;
	Result<AbstractSyntaxTree, std::string> parse_result;
	Result<int, std::string> validate_result;
	std::string conf_data, error_msg;
	std::deque<Token> tokens;
	AbstractSyntaxTree ast;

	read_result = get_configration_file_contents(file_path);
	if (read_result.is_err()) {
		error_msg = read_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	conf_data = read_result.get_ok_value();

	tokenize_result = tokenize(conf_data);
	if (tokenize_result.is_err()) {
		error_msg = tokenize_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	tokens = tokenize_result.get_ok_value();

	parse_result = parse(tokens);
	if (parse_result.is_err()) {
		error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	ast = parse_result.get_ok_value();

	validate_result = validate_ast(ast);
	if (validate_result.is_err()) {
		error_msg = validate_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

	// ast -> http_config_

	this->result_ = Result<int, std::string>::ok(OK);
}


Parser::Parser(const Parser &other) {
	*this = other;
}


Parser::~Parser() {}


Parser &Parser::operator=(const Parser &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->http_config_ = rhs.http_config_;
	this->result_ = rhs.result_;
	return *this;
}


Result<std::string, std::string> Parser::get_configration_file_contents(const char *file_path) {
	FileHandler file_handler(file_path, CONFIG_FILE_EXTENSION);
	Result<int, std::string> file_result;
	std::string file_contents, error_msg;

	file_result = file_handler.get_result();
	if (file_result.is_err()) {
		error_msg = file_result.get_err_value();
		return Result<std::string, std::string>::err(error_msg);
	}
	file_contents = file_handler.get_contents();
	return Result<std::string, std::string>::ok(file_contents);
}


Result<std::deque<Token>, std::string> Parser::tokenize(const std::string &conf_data) {
	std::deque<Token> tokens;
	(void)conf_data;

	return Result<std::deque<Token>, std::string>::ok(tokens);
}


Result<AbstractSyntaxTree, std::string> Parser::parse(const std::deque<Token> &tokens) {
	AbstractSyntaxTree ast;

	(void)tokens;
	return Result<AbstractSyntaxTree, std::string>::ok(ast);
}


Result<int, std::string> Parser::validate_ast(const AbstractSyntaxTree &ast) {
	(void)ast;
	return Result<int, std::string>::ok(OK);
}


Result<int, std::string> Parser::get_result() const { return result_; }

HttpConfig Parser::get_config() const { return http_config_; }
