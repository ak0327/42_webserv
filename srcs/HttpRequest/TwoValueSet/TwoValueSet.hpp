#ifndef SRCS_HTTPREQUEST_TWOVALUESET_TWOVALUESET_HPP_
#define SRCS_HTTPREQUEST_TWOVALUESET_TWOVALUESET_HPP_

#include <iostream>
#include <string>
#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class TwoValueSet: public BaseKeyValueMap
{
	private:
		std::string	_firstvalue;
		std::string _secondValue;
	public:
		TwoValueSet();
		explicit TwoValueSet(std::string const &first_value);
		TwoValueSet(const std::string &first_value, const std::string &second_value);
		TwoValueSet& operator=(const TwoValueSet &other);
		~TwoValueSet();
		std::string	get_firstvalue(void) const;
		std::string get_secondvalue(void) const;
};

#endif  // SRCS_HTTPREQUEST_TWOVALUESET_TWOVALUESET_HPP_
