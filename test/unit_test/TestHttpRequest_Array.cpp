#include "../../srcs/StringHandler/StringHandler.hpp"
#include "../../srcs/HttpRequest/ValueSet/ValueSet.hpp"
#include "../../srcs/HttpRequest/TwoValueSet/TwoValueSet.hpp"
#include "../../srcs/HttpRequest/RequestLine/RequestLine.hpp"
#include "../../srcs/HttpRequest/ValueArraySet/ValueArraySet.hpp"
#include "Date.hpp"
#include "../../srcs/HttpRequest/ValueMap/ValueMap.hpp"
#include "../../srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.hpp"
#include "../../srcs/HttpRequest/HttpRequest.hpp"
#include "gtest/gtest.h"
#include "../../includes/Color.hpp"
#include "../../srcs/Error/Error.hpp"
#include "../../srcs/Debug/Debug.hpp"
#include "Result.hpp"
#include <string>
#include <algorithm>

// GET /example-page HTTP/1.1
// Host: example.com
// Connection: close
// Link: </page1>; rel="next", </page2>; rel="prev"

bool	same_class_test_array(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず
{
	std::map<std::string, FieldValues*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValues*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
	{
		ADD_FAILURE_AT(__FILE__, line);
		return (false);
	}
	return (true);
}

bool	is_not_exist_array(int line, const char *key, HttpRequest &target) // 同名関数の使い回しがわからず
{
	std::map<std::string, FieldValues*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValues*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
		return (true);
	ADD_FAILURE_AT(__FILE__, line);
	return (false);
}

// GET /example HTTP/1.1\r\n
// Host: www.example.com\r\nAccept-CH: DPR, Width, Viewport-Width\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\n
// Access-Control-Allow-Methods: GET, POST, PUT\r\n
// Access-Control-Request-Headers: Content-Type, Authorization\r\n
// Access-Control-Expose-Headers: X-Custom-Header, Content-Length\r\n
// Allow: GET, POST, PUT\r\nClear-Site-Data: \"cache\", \"cookies\"\r\n
// Content-Encoding: gzip, br\r\n
// Content-Language: en-US\r\n
// If-Match: \"123456789\"\r\n
// If-None-Match: \"987654321\"\r\n
// Transfer-Encoding: chunked, gzip\r\n
// Upgrade: WebSocket\r\nVary: User-Agent\r\n
// WWW-Authenticate: Basic realm=\"Secure Area\"\r\n

void	compare_vectors_report_array(std::vector<std::string> target_vector, std::vector<std::string> subject_vector, size_t line)
{
	std::vector<std::string>::iterator itr_now = target_vector.begin();
	while (itr_now != target_vector.end())
	{
		if (std::find(subject_vector.begin(), subject_vector.end(), *itr_now) == subject_vector.end())
		{
			std::cout << *itr_now << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, line);
		}
		itr_now++;
	}
}

TEST(Array, Array_TEST)
{
	const std::string TEST_REQUEST = "GET /example HTTP/1.1\r\nHost: www.example.com\r\nAccept-CH: DPR, Width, Viewport-Width\r\nAccess-Control-Allow-Headers: Authorization, ,,Content-Type\r\nAccess-Control-Allow-Methods: GET, POST, PUT\r\nAccess-Control-Request-Headers: Content-Type, Authorization\r\nAccess-Control-Expose-Headers: X-Custom-Header, Content-Length\r\nAllow: GET, POST, PUT\r\nClear-Site-Data: \"cache\", \"cookies\"\r\nContent-Encoding: gzip, br\r\nContent-Language: en-US\r\nIf-Match: \"123456789\"\r\nIf-None-Match: \"987654321\"\r\nTransfer-Encoding: chunked, gzip\r\nUpgrade: WebSocket\r\nVary: User-Agent\r\nWWW-Authenticate: Basic realm=\"Secure Area\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	if (same_class_test_array(__LINE__, "Access-Control-Allow-Methods", httprequest_test1) == true)
	{
		ValueArraySet* val7 = static_cast<ValueArraySet*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Methods"));
		std::vector<std::string> vector7;
		// GET, POST, PUT, DELETE
		vector7.push_back("GET");
		vector7.push_back("POST");
		vector7.push_back("PUT");
		compare_vectors_report_array(val7->get_value_array(), vector7, 117);
	}
}
