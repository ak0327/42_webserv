#pragma once

# include <string>
# include <vector>

class ConfigHandlingString
{
	private:
		ConfigHandlingString();
		ConfigHandlingString(const ConfigHandlingString &other);
		~ConfigHandlingString();
		ConfigHandlingString &operator=(const ConfigHandlingString &other);

	public:
		static bool is_ignore_line(const std::string &config_line);
		static bool is_block_end(const std::string &config_line);
		static bool is_block_start(const std::string &block_end_word);

		static bool show_error_message(const std::string &config_line, const int &error_type);
		static bool ready_boolean_field_value(const std::string &field_value);

		static int is_field_header(const std::string &config_line, size_t *pos);
		static int is_field_value(const std::string &config_line, size_t *pos);
		static int ready_int_field_value(const std::string &field_value);

		static size_t ready_size_t_field_value(const std::string &field_value);

		static std::vector<std::string> ready_string_vector_field_value(const std::string &field_value);
};
