#pragma once

# include <string>
# include <vector>

class LocationConfig;
class ServerConfig;

class ConfigHandlingString
{
	private:
		ConfigHandlingString();
		ConfigHandlingString(const ConfigHandlingString &other);
		~ConfigHandlingString();
		ConfigHandlingString &operator=(const ConfigHandlingString &other);

	public:
		static bool show_error_message(const std::string &config_line, const int &error_type);
		static bool ready_boolean_field_value(const std::string &field_value);

		static int ready_int_field_value(const std::string &field_value);
		static int input_field_key_field_value(const std::string &config_line,
												LocationConfig *location_config);
		static int input_field_key_field_value(const std::string &config_line,
												ServerConfig *server_config,
												std::vector<std::string> *field_header_vector);
		static void get_field_header_and_field_value(const std::string &config_line,
													 std::string *ret_field_header,
													 std::string *ret_field_value);
		static size_t ready_size_t_field_value(const std::string &field_value);

		static std::vector<std::string> ready_string_vector_field_value(const std::string &field_value);
};
