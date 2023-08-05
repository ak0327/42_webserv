#include "HandlingString.hpp"

int main()
{
	if (HandlingString::check_lastword_semicoron("aaa;") == true)
		std::cout << "this is semicoron last" << std::endl;
	else
		std::cout << "this is NOT semicoron last" << std::endl;
}
