#include <string>
#include <iostream>

int main() {
	std::string str1 = "";
	std::string str2 = "\0";
	std::string str3 = "\0\0\0a";

	std::cout << "str1: empty:" << std::boolalpha << str1.empty() << ", len:" << str1.length() << std::endl;
	std::cout << "str2: empty:" << std::boolalpha << str2.empty() << ", len:" << str2.length() << std::endl;
	std::cout << "str3: empty:" << std::boolalpha << str3.empty() << ", len:" << str3.length() << std::endl;

}