#ifndef VALUEWEIGHTARRAYSET_HPP
#define VALUEWEIGHTARRAYSET_HPP

#include <string>
#include <map>
#include "HandlingString.hpp"

class ValueWeightArraySet: public KeyValueMap
{
	private:
		std::map<std::string, double> _valueweight_set;//map型で入れるが、どうせなら重みを加味したようなインプットの流れにしておけば取り出す時に非常に楽になるのでは？
		
		ValueWeightArraySet();
		ValueWeightArraySet &operator=(const ValueWeightArraySet &other);
	
	public:
		ValueWeightArraySet(std::map<std::string, double> &valueweight_set);
		~ValueWeightArraySet();

		std::map<std::string, double> get_valueweight_set(void) const;
};

#endif