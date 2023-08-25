#include "../includes/ValueInsertMethod.hpp"

ValueWeightArraySet	ValueInsertMethod::ready_accept(const std::string &value)
{
	ValueWeightArraySet	accept;
	std::stringstream	ss(value);
	std::string			line;

	while(std::getline(ss, line, ','))
	{
		if (line.find(';') != std::string::npos)
			accept.append_valueweight_set(HandlingString::skipping_emptyword(line));
		else
			accept.append_valueweight_set(HandlingString::skipping_emptyword(line), 1.0);
	}
	return (accept);
}