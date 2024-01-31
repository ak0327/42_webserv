#include <fstream>
#include "webserv.hpp"
#include "Configuration.hpp"
#include "Constant.hpp"
#include "FileHandler.hpp"
#include "Token.hpp"
#include "Parser.hpp"

Configuration::Configuration(const char *file_path) {
	Parser parser;
	Result<int, std::string> parse_result;
	std::string error_msg;

	parser = Parser(file_path);
	parse_result = parser.get_result();
	if (parse_result.is_err()) {
		error_msg = parse_result.get_err_value();
		this->result_ = Result<int, std::string>::err(error_msg);
		return;
	}

	this->http_config_ = parser.get_config();
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

	this->result_ = rhs.result_;
	return *this;
}


Result<int, std::string> Configuration::get_result() { return this->result_; }


std::string Configuration::get_default_port() {
	// todo: default portをhttp_config_から取得
	return "80";
}

std::string Configuration::get_default_server_name() {
	// todo: default server_nameをhttp_config_から取得
	return "";
}

std::string Configuration::get_root(const std::string &server_name,
									const std::string &location) {
	(void)server_name;
	(void)location;
	// todo: default rootをhttp_config_から取得
	return "www";
}

std::string Configuration::get_error_page(int status_code) {
	(void)status_code;
	// todo: status_codeに対応するerror_pageをhttp_config_から取得
	return "404.html";
}

std::vector<std::string> Configuration::get_index(const std::string &server_name,
												  const std::string &location) {
	std::vector<std::string> index;
	(void)server_name;
	(void)location;
	// todo: server_name, locationに対応するindexをhttp_config_から取得
	index.push_back("index.html");
	return index;
}

std::string Configuration::get_index_page(const std::string &server_name,
										  const std::string &location) {
	std::vector<std::string> index;

	index = get_index(server_name, location);
	// todo: はじめに見つかったindexをindex pageとして返す
	return index[0];
}

bool Configuration::get_autoindex(const std::string &server_name,
								  const std::string &location) {
	(void)server_name;
	(void)location;
	// todo: server_name, locationに対応するautoindexをhttp_config_から取得
	return false;
}

bool Configuration::is_method_allowed(const std::string &server_name,
									  const std::string &location,
									  const std::string &method) {
	(void)server_name;
	(void)location;
	(void)method;
	// todo: server_name, locationにおけるmethodの使用可否をhttp_config_から取得
	return true;
}

std::size_t Configuration::get_max_body_size(const std::string &server_name,
											 const std::string &location) {
	(void)server_name;
	(void)location;

	// todo: server_name, locationで許容されるmax_body_sizeをhttp_config_から取得
	const std::size_t KB = 1024;
	const std::size_t MB = KB * KB;
	return 20 * MB;
}
