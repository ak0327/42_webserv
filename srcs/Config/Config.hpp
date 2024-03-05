#pragma once

# include <deque>
# include <map>
# include <string>
# include <set>
# include <utility>
# include <vector>
# include "Constant.hpp"
# include "ConfigParser.hpp"
# include "Result.hpp"
# include "Token.hpp"
# include "Tokenizer.hpp"

class Config {
 public:
	explicit Config(const char *file_path);
	Config(const Config &other);
	~Config();

	Config &operator=(const Config &rhs);

    bool is_err() const;

    // getter
    Result<int, std::string> result() const;
    time_t keepalive_timeout() const;
    std::map<ServerInfo, const ServerConfig *> get_server_configs() const;
    Result<ServerConfig, int> get_server_config(const ServerInfo &server_info) const;
    Result<ServerConfig, std::string> get_server_config(const AddressPortPair &address_port_pair,
                                                        const HostPortPair &host_port_pair) const;
    static Result<std::string, int> get_matching_location(const ServerConfig &server_config,
                                                          const std::string &target_path);

    static Result<std::string, StatusCode> get_indexed_path(const ServerConfig &server_config,
                                                            const std::string &target_path);

    static Result<std::string, int> get_root(const ServerConfig &server_config,
                                             const std::string &target_path);
    Result<std::string, int> get_root(const ServerInfo &server_info,
                                      const std::string &target_path) const;
    Result<std::string, int> get_root(const AddressPortPair &address_port_pair,
                                      const std::string &target_path) const;

    static Result<std::string, int> get_index(const ServerConfig &server_config,
                                              const std::string &target_path);
    Result<std::string, int> get_index(const ServerInfo &server_info,
                                       const std::string &target_path) const;
    Result<std::string, int> get_index(const AddressPortPair &address_port_pair,
                                       const std::string &target_path) const;

    static Result<std::string, int> get_error_page_path(const ServerConfig &server_config,
                                                        const std::string &target_path,
                                                        const StatusCode &code);
    static Result<std::string, int> get_error_page(const ServerConfig &server_config,
                                                   const std::string &target_path,
                                                   const StatusCode &code);
    Result<std::string, int> get_error_page(const ServerInfo &server_info,
                                            const std::string &target_path,
                                            const StatusCode &code) const;
    Result<std::string, int> get_error_page(const AddressPortPair &address_port_pair,
                                            const std::string &target_path,
                                            const StatusCode &code) const;

    static Result<bool, int> is_autoindex_on(const ServerConfig &server_config,
                                             const std::string &target_path);
    Result<bool, int> is_autoindex_on(const ServerInfo &server_info,
                                      const std::string &target_path) const;
    Result<bool, int> is_autoindex_on(const AddressPortPair &address_port_pair,
                                      const std::string &target_path) const;

    static Result<LimitExceptDirective, int> limit_except(const ServerConfig &server_config,
                                                          const std::string &target_path);

    static Result<bool, int> is_method_allowed(const ServerConfig &server_config,
                                               const std::string &target_path,
                                               const Method &method);
    Result<bool, int> is_method_allowed(const ServerInfo &server_info,
                                        const std::string &target_path,
                                        const Method &method) const;
    Result<bool, int> is_method_allowed(const AddressPortPair &address_port_pair,
                                        const std::string &target_path,
                                        const Method &method) const;

    static Result<bool, int> is_redirect(const ServerConfig &server_config,
                                         const std::string &target_path);
    Result<bool, int> is_redirect(const ServerInfo &server_info,
                                  const std::string &target_path) const;
    Result<bool, int> is_redirect(const AddressPortPair &address_port_pair,
                                  const std::string &target_path) const;

    static ReturnDirective get_return(const ServerConfig &server_config,
                                      const std::string &target_path);

    static Result<ReturnDirective, int> get_redirect(const ServerConfig &server_config,
                                                     const std::string &target_path);
    Result<ReturnDirective, int> get_redirect(const ServerInfo &server_info,
                                              const std::string &target_path) const;
    Result<ReturnDirective, int> get_redirect(const AddressPortPair &address_port_pair,
                                              const std::string &target_path) const;

    static Result<std::size_t, int> get_max_body_size(const ServerConfig &server_config,
                                                      const std::string &target_path);
    Result<std::size_t, int> get_max_body_size(const ServerInfo &server_info,
                                               const std::string &target_path) const;
    Result<std::size_t, int> get_max_body_size(const AddressPortPair &address_port_pair,
                                               const std::string &target_path) const;

    static Result<bool, int> is_cgi_mode_on(const ServerConfig &server_config,
                                             const std::string &target_path);
    Result<bool, int> is_cgi_mode_on(const ServerInfo &server_info,
                                      const std::string &target_path) const;
    Result<bool, int> is_cgi_mode_on(const AddressPortPair &address_port_pair,
                                      const std::string &target_path) const;

    static Result<std::set<std::string>, int> get_cgi_extension(const ServerConfig &server_config,
                                                                const std::string &target_path);

    Result<std::set<std::string>, int> get_cgi_extension(const ServerInfo &server_info,
                                                         const std::string &target_path) const;

    Result<std::set<std::string>, int> get_cgi_extension(const AddressPortPair &address_port_pair,
                                                         const std::string &target_path) const;

    static bool is_cgi_extension(const ServerConfig &server_config,
                                 const std::string &target_path);
    bool is_cgi_extension(const ServerInfo &server_info,
                          const std::string &target_path) const;
    bool is_cgi_extension(const AddressPortPair &address_port_pair,
                          const std::string &target_path) const;

    static time_t get_cgi_timeout(const ServerConfig &server_config,
                                  const std::string &target_path);
    time_t get_cgi_timeout(const ServerInfo &server_info,
                           const std::string &target_path) const;
    time_t get_cgi_timeout(const AddressPortPair &address_port_pair,
                           const std::string &target_path) const;


    static bool is_exact_match(const std::string &pattern, const std::string &target);
    static bool is_prefix_match(const std::string &pattern, const std::string &target);

    Result<ServerConfig, int> get_default_server(const AddressPortPair &pair) const;

 private:
	HttpConfig http_config_;
    std::map<ServerInfo, const ServerConfig *> server_configs_;
    std::map<AddressPortPair, const ServerConfig *> default_servers_;

    Result<int, std::string> result_;

    Result<int, std::string> set_default_servers();
    Result<int, std::string> set_default_server_to_default_listen();
    void set_default_server_to_first_listen();
    void set_server_configs();


    static Result<LocationConfig, int> get_location_config(const ServerConfig &server_config,
                                                           const std::string &location_path);
};


std::ostream &operator<<(std::ostream &out,
                         const std::map<AddressPortPair, const ServerConfig *> &default_servers);
std::ostream &operator<<(std::ostream &out, const AddressPortPair &pair);
