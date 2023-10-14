#ifndef SRCS_NUMERICHANDLE_NUMERICHANDLE_HPP_
#define SRCS_NUMERICHANDLE_NUMERICHANDLE_HPP_

#include <climits>
#include <sstream>
#include <string>

class NumericHandle
{
	private:
		NumericHandle();
		NumericHandle(const NumericHandle &other);
		NumericHandle& operator=(const NumericHandle &other);
		~NumericHandle();
	public:
		static	bool						is_positive_under_intmax_double(const std::string &value);
		static	bool						is_positive_and_under_intmax_int(const std::string &word);
		static	double						str_to_double(const std::string &num_str);
		static	int							str_to_int(const std::string &word);
		static	int							to_digit(const char &c);
		static	std::string					int_to_str(int num);
};

#endif  // SRCS_NUMERICHANDLE_NUMERICHANDLE_HPP_
