#ifndef VALUEWEIGHTARRAYSET_HPP
#define VALUEWEIGHTARRAYSET_HPP

#include <string>
#include <map>
#include "HandlingString.hpp"

class ValueWeightArraySet
{
	private:
		std::map<std::string, double> _valueweight_set;//map型で入れるが、どうせなら重みを加味したようなインプットの流れにしておけば取り出す時に非常に楽になるのでは？
		
		ValueWeightArraySet(const ValueWeightArraySet &other);
		ValueWeightArraySet &operator=(const ValueWeightArraySet &other);
	
	public:
		ValueWeightArraySet();
		ValueWeightArraySet(const std::string &other);
		~ValueWeightArraySet();

		std::map<std::string, double> get_valueweight_set(void) const;

		void	append_valueweight_set(const std::string &value, double weight);
};

#endif