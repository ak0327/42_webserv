#pragma once

# include <string>
# include <vector>
# include "LocationConfig.hpp"
# include "ServerConfig.hpp"

class LocationConfig;
class ServerConfig;

class IsConfigFormat
{
	private:
		IsConfigFormat();
		IsConfigFormat(const IsConfigFormat &other);
		IsConfigFormat& operator=(const IsConfigFormat &other);
		~IsConfigFormat();

	public:
		static int is_start_location_block(const std::string &config_line,
										   std::string *config_location_path);
		static int is_start_location_block(const std::string &config_line);
		static int is_start_server_block(const std::string &config_line,
										 bool *in_server_block);
		static int is_location_block_format(const std::string &config_line);
		static int is_server_block_format(const std::string	&config_line,
										  std::vector<std::string> field_headers);
		static int input_field_key_field_value(const std::string &config_line,
											   LocationConfig *server_config);  // todo: server_config??
		static int input_field_key_field_value(const std::string &config_line,
											   ServerConfig	*server_config,
											   std::vector<std::string> *field_header_vector);
};
