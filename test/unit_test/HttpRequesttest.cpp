#include "../../srcs/HandlingString/HandlingString.hpp"
#include "../../srcs/HttpRequest/ValueSet/ValueSet.hpp"
#include "../../srcs/HttpRequest/TwoValueSet/TwoValueSet.hpp"
#include "../../srcs/HttpRequest/RequestLine/RequestLine.hpp"
#include "../../srcs/HttpRequest/ValueArraySet/ValueArraySet.hpp"
#include "../../srcs/HttpRequest/ValueDateSet/ValueDateSet.hpp"
#include "../../srcs/HttpRequest/ValueMap/ValueMap.hpp"
#include "../../srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../../srcs/HttpRequest/HttpRequest/HttpRequest.hpp"
#include "gtest/gtest.h"

const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";

int main()
{
	HttpRequest some(TEST_REQUEST);
	DEBUG_PRINT(some.show_requestinfs());
}

//g++ *.cpp ../HandleString/HandlingString.cpp