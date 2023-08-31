#ifndef BASEKEYVALUEMAP_HPP
#define BASEKEYVALUEMAP_HPP

#include <map>
#include <string>

class	BaseKeyValueMap
{
	private:
		BaseKeyValueMap(const KeyValueMap &other);

	public:
		virtual ~BaseKeyValueMap();
};

#endif