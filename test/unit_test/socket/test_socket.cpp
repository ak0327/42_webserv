#include <vector>
#include <string>


int main()
{
	std::vector<std::string> test_portset;
	test_portset.push_back("4242");
	test_portset.push_back("2424");

	std::vector<std::string>::iterator	it = test_portset.begin();

	while (it != test_portset.end())
	{
		
		it++;
	}
}