#include <ctype.h>
#include <algorithm>
#include <climits>
#include <iostream>
#include <limits>
#include <sstream>
#include <vector>
#include "Color.hpp"
#include "Constant.hpp"
#include "StringHandler.hpp"
#include "HttpMessageParser.hpp"


namespace {

bool is_in_int_range(int before_x10_num,
					 int add_num) {
	int max_div, max_mod;

	if (before_x10_num == INT_MAX || before_x10_num == INT_MIN) {
		return false;
	}
	if (before_x10_num > 0) {
		max_div = INT_MAX / 10;
		max_mod = INT_MAX % 10;
	} else {
		max_div = -(INT_MIN / 10);
		max_mod = -(INT_MIN % 10);
	}
	if (std::abs(before_x10_num) < max_div) {
		return true;
	}
	if (std::abs(before_x10_num) == max_div && max_mod == add_num) {
		return true;
	}
	return false;
}

bool is_in_long_range(long before_x10_num,
					  long add_num) {
	long max_div, max_mod;

	if (before_x10_num == LONG_MAX || before_x10_num == LONG_MIN) {
		return false;
	}
	if (before_x10_num > 0) {
		max_div = LONG_MAX / 10;
		max_mod = LONG_MAX % 10;
	} else {
		max_div = -(LONG_MIN / 10);
		max_mod = -(LONG_MIN % 10);
	}
	if (std::abs(before_x10_num) < max_div) {
		return true;
	}
	if (std::abs(before_x10_num) == max_div && max_mod == add_num) {
		return true;
	}
	return false;
}

}  // namespace

////////////////////////////////////////////////////////////////////////////////

namespace StringHandler {

int to_digit(const char &c) {
	return (c - '0');
}


int stoi(const std::string &str, std::size_t *idx, bool *overflow) {
	std::size_t	i;
	int 		num, digit, sign;

	if (overflow) { *overflow = false; }
	if (idx) { *idx = 0; }

	i = 0;
	while (std::isspace(str[i])) {
		i++;
	}

	sign = 1;
	if (str[i] == SIGN_PLUS || str[i] == SIGN_MINUS) {
		if (str[i] == SIGN_MINUS) {
			sign = -1;
		}
		i++;
	}

	num = 0;
	while (std::isdigit(str[i])) {
		digit = to_digit(str[i]);
		if (!is_in_int_range(num, digit)) {
			num = (sign == 1) ? INT_MAX : INT_MIN;
			if (overflow) { *overflow = true; }
			if (idx) { *idx = i; }
			return num;
		}
		num = num * 10 + sign * digit;
		i++;
	}

	if (idx) { *idx = i; }
	return num;
}


long stol(const std::string &str, std::size_t *idx, bool *overflow) {
	std::size_t	i;
	long 		num;
	int			digit, sign;

	if (overflow) { *overflow = false; }
	if (idx) { *idx = 0; }

	i = 0;
	while (std::isspace(str[i])) {
		i++;
	}

	sign = 1;
	if (str[i] == SIGN_PLUS || str[i] == SIGN_MINUS) {
		if (str[i] == SIGN_MINUS) {
			sign = -1;
		}
		i++;
	}

	num = 0;
	while (std::isdigit(str[i])) {
		digit = to_digit(str[i]);
		if (!is_in_long_range(num, digit)) {
			num = (sign == 1) ? LONG_MAX : LONG_MIN;
			if (overflow) { *overflow = true; }
			if (idx) { *idx = i; }
			return num;
		}
		num = num * 10 + sign * digit;
		i++;
	}

	if (idx) { *idx = i; }
	return num;
}


std::string to_string(int num) {
	std::ostringstream oss;
	oss << num;
	return oss.str();
}


std::string to_string(long num) {
	std::ostringstream oss;
	oss << num;
	return oss.str();
}


std::string to_string(std::size_t num) {
    std::ostringstream oss;
    oss << num;
    return oss.str();
}


std::string to_lower(const std::string &str) {
    if (str.empty()) { return str; }

	std::string lower_str;
	char c;

	for (std::size_t pos = 0; pos < str.length(); ++pos) {
		c = static_cast<char>(
				std::tolower(static_cast<unsigned char>(str[pos])));
		lower_str += c;
	}
	return lower_str;
}

std::string to_upper(const std::string &str) {
    if (str.empty()) { return str; }

    std::string upper_str;
    char c;

    for (std::size_t pos = 0; pos < str.length(); ++pos) {
        c = static_cast<char>(
                std::toupper(static_cast<unsigned char>(str[pos])));
        upper_str += c;
    }
    return upper_str;
}


// todo: mv end_pos
Result<std::string, int> parse_pos_to_delimiter(const std::string &src_str,
												std::size_t start_pos,
												std::size_t *end_pos,
												char tail_delimiter) {
	std::size_t delim_pos, len;
	std::string	ret_str;

	if (end_pos) { *end_pos = start_pos; }

	if (src_str.empty() || src_str.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	if (tail_delimiter == '\0') {
		ret_str = src_str.substr(start_pos);
		if (end_pos) { *end_pos = src_str.length(); }
		return Result<std::string, int>::ok(ret_str);
	}

	delim_pos = src_str.find(tail_delimiter, start_pos);
	if (delim_pos == std::string::npos) {
		return Result<std::string, int>::err(ERR);
	}
	len = delim_pos - start_pos;

	ret_str = src_str.substr(start_pos, len);

	if (end_pos) { *end_pos = start_pos + len; }
	return Result<std::string, int>::ok(ret_str);
}


Result<std::string, int> parse_pos_to_wsp(const std::string &str,
										  std::size_t start_pos,
										  std::size_t *end_pos) {
	std::size_t pos, len;
	std::string	ret_str;

	if (end_pos) { *end_pos = start_pos; }

	pos = start_pos;
	if (str.empty() || str.length() < start_pos) {
		return Result<std::string, int>::err(ERR);
	}

	while (str[pos] && !HttpMessageParser::is_whitespace(str[pos])) {
		++pos;
	}
	len = pos - start_pos;

	ret_str = str.substr(start_pos, len);

	if (end_pos) { *end_pos = start_pos + len; }
	return Result<std::string, int>::ok(ret_str);
}


bool is_char_in_str(char c, const std::string &str) {
	return str.find(c) != std::string::npos;
}


bool is_valid_extension(const std::string &extension) {
    if (extension.empty()) {
        return false;
    }
    for (std::size_t pos = 0; pos < extension.length(); ++pos) {
        if (!std::isalnum(extension[pos])) {
            return false;
        }
    }
    return true;
}


bool is_valid_file_name(const std::string &path) {
    std::string file_name = StringHandler::get_file_name(path);
    std::string extension = get_extension(file_name);

    if (file_name.empty() || extension.empty()) {
        return false;
    }

    std::size_t name_len = file_name.length() - extension.length() - 1;
    for (std::size_t pos = 0; pos < name_len; ++pos) {
        if (!std::isprint(static_cast<unsigned char>(file_name[pos]))) {
            return false;
        }
    }
    if (!StringHandler::is_valid_extension(extension)) {
        return false;
    }
    return true;
}


bool has_trailing_slash(const std::string &path) {
    if (path.empty()) {
        return false;
    }
    return path[path.length() - 1] == '/';
}


std::string get_file_name(const std::string &path) {
    std::size_t slash_pos;

    slash_pos = path.find_last_of(PATH_DELIM);
    if (slash_pos == std::string::npos) {
        return std::string(path);
    }
    return path.substr(slash_pos + 1);
}


std::string get_extension(const std::string &path) {
    std::size_t ext_pos, slash_pos;

    ext_pos = path.find_last_of(EXTENSION_DELIM);
    if (ext_pos == std::string::npos || ext_pos == 0) {
        return std::string(EMPTY);
    }
    slash_pos = path.find_last_of(PATH_DELIM);
    if (slash_pos != std::string::npos && ext_pos < slash_pos) {
        return std::string(EMPTY);
    }
    return path.substr(ext_pos + 1);
}


std::string unquote(const std::string &quoted) {
    if (!HttpMessageParser::is_quoted_string(quoted)) {
        return quoted;
    }
    std::string unquote = quoted.substr(1, quoted.length() - 2);
    return unquote;
}


std::string decode(const std::string& encoded) {
    std::string decoded;
    std::istringstream iss(encoded);
    char ch;

    while (iss.get(ch)) {
        if (ch == '%' && !iss.eof()) {
            char hex_str[3] = {0};
            iss.read(hex_str, 2);

            if (std::isxdigit(hex_str[0]) && std::isxdigit(hex_str[1])) {
                char decoded_char = static_cast<char>(std::strtol(hex_str, NULL, 16));
                decoded.push_back(decoded_char);
            } else {
                decoded.push_back(ch);
                if (hex_str[0] != '\0') {
                    decoded.push_back(hex_str[0]);
                }
                if (hex_str[1] != '\0') {
                    decoded.push_back(hex_str[1]);
                }
            }
        } else {
            decoded.push_back(ch);
        }
    }
    return decoded;
}


// "../" -> "/"
std::string normalize_to_absolute_path(const std::string& path) {
    std::vector<std::string> segments;
    std::istringstream path_stream(path);
    std::string segment;
    std::string normalized;
    bool ends_with_slash = !path.empty() && (path[path.length() - 1] == '/');

    while (std::getline(path_stream, segment, '/')) {
        if (segment == "..") {
            if (!segments.empty()) {
                segments.pop_back();
            }
        } else if (!segment.empty() && segment != ".") {
            segments.push_back(segment);
        }
    }

    for (std::size_t i = 0; i < segments.size(); ++i) {
        normalized += "/";
        normalized += segments[i];
    }

    if (ends_with_slash && !normalized.empty() && normalized[normalized.length() - 1] != '/') {
        normalized += "/";
    }
    return normalized.empty() ? "/" : normalized;
}


}  // namespace StringHandler
