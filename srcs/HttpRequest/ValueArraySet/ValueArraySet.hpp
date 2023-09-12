#ifndef SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_
#define SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_

#include <string>
#include <vector>
#include <iostream>

#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class ValueArraySet: public BaseKeyValueMap
{
	private:
		std::vector<std::string> _value_array;
	public:
		ValueArraySet();
		ValueArraySet(const ValueArraySet &other);
		explicit ValueArraySet(const std::vector<std::string> &value_array);
		explicit ValueArraySet &operator=(const ValueArraySet &other);
		~ValueArraySet();
		std::vector<std::string>	get_value_array(void) const;
		void				show_value(void);
};

#endif  // SRCS_HTTPREQUEST_VALUEARRAYSET_VALUEARRAYSET_HPP_
