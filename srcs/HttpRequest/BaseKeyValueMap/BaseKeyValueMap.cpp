#include "BaseKeyValueMap.hpp"

BaseKeyValueMap::BaseKeyValueMap(){}

BaseKeyValueMap::BaseKeyValueMap(const BaseKeyValueMap &other)
{
	if (&other == this)
		return;
}

BaseKeyValueMap::~BaseKeyValueMap(){}
