#pragma once

# include <deque>
# include <string>
# include <vector>
# include "AbstractSyntaxTree.hpp"
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

	// -- tmp: 既存のテスト用 --
	Configuration() : ip_("127.0.0.1"), port_("8080") {}
	void set_ip(const std::string &ip) { ip_ = ip; }
	void set_port(const std::string &port) { port_ = port; }
	std::string get_server_ip() const { return ip_; }
	std::string get_server_port() const { return port_; }
	// ------------------------

 private:
	HttpConfig http_config_;
	Result<int, std::string> result_;

	// -- tmp: 既存のテスト用 --
	std::string ip_;
	std::string port_;
	// ------------------------
};
