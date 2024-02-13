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

    // getter
	Result<int, std::string> get_result() const;
    std::map<ServerInfo, const ServerConfig *> get_server_configs() const;
    Result<ServerConfig, int> get_server_config(const ServerInfo &server_info) const;


    static std::string get_root(const ServerConfig &server_config,
                                const std::string &location_path);
    Result<std::string, int> get_root(const ServerInfo &server_info,
                                      const std::string &location_path) const;
    Result<std::string, int> get_root(const AddressPortPair &address_port_pair,
                                      const std::string &location_path) const;

    static std::string get_index(const ServerConfig &server_config,
                                 const std::string &location_path);
    Result<std::string, int> get_index(const ServerInfo &server_info,
                                       const std::string &location_path) const;
    Result<std::string, int> get_index(const AddressPortPair &address_port_pair,
                                       const std::string &location_path) const;

    static Result<std::string, int> get_error_page(const ServerConfig &server_config,
                                                   const std::string &location_path,
                                                   const StatusCode &code);
    Result<std::string, int> get_error_page(const ServerInfo &server_info,
                                            const std::string &location_path,
                                            const StatusCode &code) const;
    Result<std::string, int> get_error_page(const AddressPortPair &address_port_pair,
                                            const std::string &location_path,
                                            const StatusCode &code) const;

    static bool is_autoindex_on(const ServerConfig &server_config,
                                const std::string &location_path);
    Result<bool, int> is_autoindex_on(const ServerInfo &server_info,
                                      const std::string &location_path) const;
    Result<bool, int> is_autoindex_on(const AddressPortPair &address_port_pair,
                                      const std::string &location_path) const;

    static bool is_method_allowed(const ServerConfig &server_config,
                                  const std::string &location_path,
                                  const Method &method);
    Result<bool, int> is_method_allowed(const ServerInfo &server_info,
                                        const std::string &location_path,
                                        const Method &method) const;
    Result<bool, int> is_method_allowed(const AddressPortPair &address_port_pair,
                                        const std::string &location_path,
                                        const Method &method) const;

    static bool is_redirect(const ServerConfig &server_config,
                            const std::string &location_path);
    Result<bool, int> is_redirect(const ServerInfo &server_info,
                                  const std::string &location_path) const;
    Result<bool, int> is_redirect(const AddressPortPair &address_port_pair,
                                  const std::string &location_path) const;

    static Result<ReturnDirective, int> get_redirect(const ServerConfig &server_config,
                                                     const std::string &location_path);
    Result<ReturnDirective, int> get_redirect(const ServerInfo &server_info,
                                              const std::string &location_path) const;
    Result<ReturnDirective, int> get_redirect(const AddressPortPair &address_port_pair,
                                              const std::string &location_path) const;

    static std::size_t get_max_body_size(const ServerConfig &server_config,
                                         const std::string &location_path);
    Result<std::size_t, int> get_max_body_size(const ServerInfo &server_info,
                                               const std::string &location_path) const;
    Result<std::size_t, int> get_max_body_size(const AddressPortPair &address_port_pair,
                                               const std::string &location_path) const;

 private:
	HttpConfig http_config_;
    std::map<ServerInfo, const ServerConfig *> server_configs_;
    std::map<AddressPortPair, const ServerConfig *> default_servers_;

    Result<int, std::string> result_;

    Result<int, std::string> set_default_servers();
    Result<int, std::string> set_default_server_to_default_listen();
    void set_default_server_to_first_listen();
    void set_server_configs();

    Result<ServerConfig, int> get_default_server(const AddressPortPair &pair) const;

    static Result<LocationConfig, int> get_location_config(const ServerConfig &server_config,
                                                           const std::string &location_path);
};


std::ostream &operator<<(std::ostream &out,
                         const std::map<AddressPortPair, const ServerConfig *> &default_servers);
std::ostream &operator<<(std::ostream &out, const AddressPortPair &pair);
