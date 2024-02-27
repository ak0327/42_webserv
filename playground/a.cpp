#include <string>
#include <iostream>

int main() {
	std::string str1 = "abc";
    std::string str2 = "abcd";

    std::size_t pos = str1.find('c');
    std::cout << str1.substr(pos + 1) << std::endl;

    pos = str2.find('c');
    std::cout << str2.substr(pos + 1) << std::endl;
    return 0;
}
