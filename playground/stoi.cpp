#include <iostream>
#include <string>

int main() {
	std::string str = "2147483648";
	std::size_t idx = 0;
	int ret;

	try {
		ret = std::stoi(str, &idx);
		std::cout << "ret:" << ret << ", idx:" << idx << ", str.len:" << str.length() << std::endl;
	}
	catch (const std::exception &e){
		std::cout << e.what() << std::endl;
		std::cout << "ret:" << ret << ", idx:" << idx << ", str.len:" << str.length() << std::endl;
	}

	return 0;
}
