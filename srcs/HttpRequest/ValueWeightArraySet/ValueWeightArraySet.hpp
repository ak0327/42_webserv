#ifndef SRCS_HTTPREQUEST_VALUEWEIGHTARRAYSET_VALUEWEIGHTARRAYSET_HPP_
#define SRCS_HTTPREQUEST_VALUEWEIGHTARRAYSET_VALUEWEIGHTARRAYSET_HPP_

#include <string>
#include <map>
#include "../../HandlingString/HandlingString.hpp"
#include "../BaseKeyValueMap/BaseKeyValueMap.hpp"

class ValueWeightArraySet: public BaseKeyValueMap
{
	private:
		std::map<std::string, double> _valueweight_set;  // map型で入れるが
		// どうせなら重みを加味したようなインプットの流れにしておけば取り出す時に非常に楽になるのでは？
	public:
		ValueWeightArraySet();
		ValueWeightArraySet(const ValueWeightArraySet &other);
		ValueWeightArraySet &operator=(const ValueWeightArraySet &other);
		explicit ValueWeightArraySet(const std::map<std::string, double> &valueweight_set);
		~ValueWeightArraySet();
		std::map<std::string, double> get_valueweight_set(void);
		void show_value();
};

#endif  // SRCS_HTTPREQUEST_VALUEWEIGHTARRAYSET_VALUEWEIGHTARRAYSET_HPP_
