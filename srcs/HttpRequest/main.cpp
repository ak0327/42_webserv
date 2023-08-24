#include "../includes/HandlingString.hpp"
#include "../includes/ValueSet.hpp"
#include "../includes/TwoValueSet.hpp"
#include "../includes/RequestLine.hpp"
#include "../includes/ValueArraySet.hpp"
#include "../includes/ValueDateSet.hpp"
#include "../includes/ValueMap.hpp"
#include "../includes/ValueWeightArraySet.hpp"
#include "../includes/HttpRequest.hpp"

std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";

int main()
{
	HttpRequest some(TEST_REQUEST);
	some.show_requestinfs();
}