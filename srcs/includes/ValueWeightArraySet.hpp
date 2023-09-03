#ifndef VALUEWEIGHTARRAYSET_HPP
#define VALUEWEIGHTARRAYSET_HPP

#include <string>
#include <map>
#include "HandlingString.hpp"

#include "BaseKeyValueMap.hpp"

class ValueWeightArraySet: public BaseKeyValueMap
{
	private:
		std::map<std::string, double> _valueweight_set;//map型で入れるが、どうせなら重みを加味したようなインプットの流れにしておけば取り出す時に非常に楽になるのでは？
	
	public:
		ValueWeightArraySet();
		ValueWeightArraySet(const ValueWeightArraySet &other);
		ValueWeightArraySet &operator=(const ValueWeightArraySet &other);
		ValueWeightArraySet(std::map<std::string, double> &valueweight_set);
		~ValueWeightArraySet();

		std::map<std::string, double> get_valueweight_set(void) const;

		void show_value();
};

#endif