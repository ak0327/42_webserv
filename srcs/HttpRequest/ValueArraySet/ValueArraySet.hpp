#ifndef SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_
#define SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_

#include <iostream>
#include <string>
#include <vector>

#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class ValueArraySet: public BaseKeyValueMap
{
	private:
		std::vector<std::string>	_value_array;
	public:
		ValueArraySet();
		explicit ValueArraySet(const std::vector<std::string> &value_array);
		ValueArraySet(const ValueArraySet &other);
		ValueArraySet &operator=(const ValueArraySet &other);
		~ValueArraySet();
		std::vector<std::string>	get_value_array(void) const;
};

#endif  // SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_
