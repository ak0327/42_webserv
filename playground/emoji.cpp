#include <iostream>
#include <sstream>

int main() {
    std::ostringstream oss;
    oss << "🍪";
    std::cout << oss.str() << std::endl;

    return 0;
}
