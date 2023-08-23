#pragma once

#include <string>

# define CONFIG_FILE_GIVEN_ARGC		2
# define CONFIG_FILE_INDEX			1

# define CONFIG_FILE_EXTENSION	"conf"
# define DEFAULT_CONFIG			"default"

# define PATH_DELIM			'/'
# define EXTENSION_DELIM	'.'

# define STAT_ERROR		(-1)
# define ERROR			(-1)
# define OK				0

# define INVALID_ARGUMENT_ERROR_MSG	"[Error] invalid argument"
# define INVALID_PATH_ERROR_MSG		"[Error] invalid file path"

std::string get_valid_config_file_path(const char *path);
bool		is_valid_config_file_path(const char *path);  // todo: static
