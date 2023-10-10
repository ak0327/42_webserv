#pragma once

# include <map>
# include <string>
# include "FieldValues.hpp"
# include "StringHandler.hpp"

class ValueWeightArraySet: public FieldValues {
	private:
		std::map<std::string, double> _valueweight_set;  // map型で入れるが
		// どうせなら重みを加味したようなインプットの流れにしておけば取り出す時に非常に楽になるのでは？
	public:
		ValueWeightArraySet();
		ValueWeightArraySet(const ValueWeightArraySet &other);
		ValueWeightArraySet& operator=(const ValueWeightArraySet &other);
		explicit ValueWeightArraySet(const std::map<std::string, double> &valueweight_set);
		~ValueWeightArraySet();
		std::map<std::string, double> get_valueweight_set(void) const;
};
