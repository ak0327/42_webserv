#include <fstream>
#include "webserv.hpp"
#include "Configuration.hpp"
#include "Constant.hpp"
#include "FileHandler.hpp"

Configuration::Configuration(const char *file_path) {
	Result<std::string, std::string> read_result;
	Result<std::deque<Token>, std::string> tokenize_result;
	Result<AbstractSyntaxTree, std::string> parse_result;
	Result<int, std::string> validate_result;
	std::string error_msg;

	read_result = get_configration_file_contents(file_path);
	if (read_result.is_err()) {
		error_msg = read_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	this->conf_data_ = read_result.get_ok_value();

	tokenize_result = tokenize(this->conf_data_);
	if (tokenize_result.is_err()) {
		error_msg = tokenize_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	this->tokens_ = tokenize_result.get_ok_value();

	parse_result = parse(this->tokens_);
	if (parse_result.is_err()) {
		error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	this->ast_ = parse_result.get_ok_value();

	validate_result = validate_ast(this->ast_);
	if (validate_result.is_err()) {
		error_msg = validate_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}
	this->result_ = Result<int, std::string>::ok(OK);
}


Configuration::Configuration(const Configuration &other) {
	*this = other;
}


Configuration::~Configuration() {}


Configuration &Configuration::operator=(const Configuration &rhs) {
	if (this == &rhs) {
		return *this;
	}

	this->conf_data_ = rhs.conf_data_;
	this->tokens_ = rhs.tokens_;
	this->ast_ = rhs.ast_;
	this->result_ = rhs.result_;
	return *this;
}


Result<int, std::string> Configuration::get_result() { return this->result_; }


Result<std::string, std::string> Configuration::get_configration_file_contents(const char *file_path) {
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


Result<std::deque<Token>, std::string> Configuration::tokenize(const std::string &conf_data) {
	(void)conf_data;
	return Result<std::deque<Token>, std::string>::ok(tokens.get_tokens());
}


Result<AbstractSyntaxTree, std::string> Configuration::parse(const std::deque<Token> &tokens) {
	AbstractSyntaxTree ast;

	(void)tokens;
	return Result<AbstractSyntaxTree, std::string>::ok(ast);
}


Result<int, std::string> Configuration::validate_ast(const AbstractSyntaxTree &ast) {
	(void)ast;
	return Result<int, std::string>::ok(OK);
}
