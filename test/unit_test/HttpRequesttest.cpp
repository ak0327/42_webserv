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
#include "../../includes/Color.hpp"
#include "../../srcs/Error/Error.hpp"
#include "../../srcs/Debug/Debug.hpp"
#include "Result.hpp"
#include <string>

void	check(std::map<std::string, std::string> target_wordmap, std::map<std::string, std::string> expected_wordmap, std::vector<std::string> keys)
{
	std::vector<std::string>::iterator itr_now = keys.begin();
	while (itr_now != keys.end())
	{
		std::map<std::string, std::string>::iterator key_check_itr = target_wordmap.begin();
		while (key_check_itr != target_wordmap.end())
		{
			if (key_check_itr->first == *itr_now)
				break;
			key_check_itr++;
		}
		if (key_check_itr == target_wordmap.end())
			ADD_FAILURE_AT(__FILE__, __LINE__);
		else
			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
		itr_now++;
	}
}

void	check(std::map<std::string, double> target_wordmap, std::map<std::string, double> expected_wordmap, std::vector<std::string> keys)
{
	std::vector<std::string>::iterator itr_now = keys.begin();
	while (itr_now != keys.end())
	{
		std::map<std::string, double>::iterator key_check_itr = target_wordmap.begin();
		while (key_check_itr != target_wordmap.end())
		{
			if (key_check_itr->first == *itr_now)
				break;
			key_check_itr++;
		}
		if (key_check_itr == target_wordmap.end())
			ADD_FAILURE_AT(__FILE__, __LINE__);
		else
			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
		itr_now++;
	}
}

void	check(const std::string &first_target_word, const std::string &second_target_word, const std::string &exp_1, const std::string &exp_2)
{
	EXPECT_EQ(first_target_word, exp_1);
	EXPECT_EQ(second_target_word, exp_2);
}

void	check(const std::string &target_word, const std::string &expected_word)
{
	EXPECT_EQ(target_word, expected_word);
}

bool	same_class_test(int raw, const char *key, HttpRequest &target)
{
	std::map<std::string, BaseKeyValueMap*>keyvaluemap = target.get_request_keyvalue_map();
	std::map<std::string, BaseKeyValueMap*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == key)
			break;
		itr_now++;
	}
	if (itr_now == keyvaluemap.end())
	{
		ADD_FAILURE_AT(__FILE__, raw);
		return (false);
	}
	return (true);
}

TEST(Request, TEST1)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nETag: some_etag\r\nUser-Agent: YourUserAgent\r\nAccept: text/html\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/index.html");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
		check( twoval->get_firstvalue(), twoval->get_secondvalue(), "www.example.com", "");
	}
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		ValueSet* val = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
		check( val->get_value_set(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "Accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept"));
		std::map<std::string, double> keyvalue;
		std::vector<std::string> keys;
		keyvalue["text/html"] = 1.0;
		keys.push_back("text/html");
		check(valweightarray->get_valueweight_set(), keyvalue, keys);
	}
}

// GET /path/to/resource HTTP/1.1
// Host: example.com
// User-Agent: YourUserAgent
// Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
// Accept-Language: en-US,en;q=0.5
// Accept-Encoding: gzip, deflate
// Connection: keep-alive
// Referer: http://www.example.com/referrer
// Cookie: session_id=12345; user=JohnDoe
// Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
// Cache-Control: no-cache
// Pragma: no-cache
// DNT: 1
// Upgrade-Insecure-Requests: 1

TEST(Request, TEST2)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\nHost: example.com\r\nUser-Agent: YourUserAgent\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nReferer: http://www.example.com/referrer\r\nCookie: session_id=12345; user=JohnDoe\r\nAuthorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nDNT: 1\r\nUpgrade-Insecure-Requests: 1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	std::cout << "here" << std::endl;
	if (same_class_test(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
		check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	}
	std::cout << "here" << std::endl;
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		ValueSet* val2 = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
		check( val2->get_value_set(), "YourUserAgent");
	}
	std::cout << "here" << std::endl;
	if (same_class_test(__LINE__, "Accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray3 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept"));
		std::cout << "here" << std::endl;
		std::map<std::string, double> keyvalue3;
		std::vector<std::string> keys3;
		std::cout << "here" << std::endl;
		keyvalue3["text/html"] = 1.0;
		keyvalue3["application/xhtml+xml"] = 1.0;
		keyvalue3["application/xml"] = 0.9;
		keyvalue3["*/*"] = 0.8;
		keys3.push_back("text/html");
		keys3.push_back("application/xhtml+xml");
		keys3.push_back("application/xml");
		keys3.push_back("*/*");
		std::cout << "here" << std::endl;
		check(valweightarray3->get_valueweight_set(), keyvalue3, keys3);
	}
	if (same_class_test(__LINE__, "Accept-Language", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray4 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept-Language"));
		std::map<std::string, double> keyvalue4;
		std::vector<std::string> keys4;
		keyvalue4["en-US"] = 1.0;
		keyvalue4["en"] = 0.5;
		keys4.push_back("en-US");
		keys4.push_back("en");
		check(valweightarray4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "Accept-Encoding", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray5 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept-Encoding"));
		std::map<std::string, double> keyvalue5;
		std::vector<std::string> keys5;
		keyvalue5["gzip"] = 1.0;
		keyvalue5["deflate"] = 0.5;
		keys5.push_back("gzip");
		keys5.push_back("deflate");
		check(valweightarray5->get_valueweight_set(), keyvalue5, keys5);
	}
	if (same_class_test(__LINE__, "Connection", httprequest_test1) == true)
	{
		ValueSet* val6 = static_cast<ValueSet*>(httprequest_test1.return_value("Connection"));
		check( val6->get_value_set(), "keep-alive");
	}
	if (same_class_test(__LINE__, "Referer", httprequest_test1) == true)
	{
		ValueSet* val7 = static_cast<ValueSet*>(httprequest_test1.return_value("Referer"));
		check( val7->get_value_set(), "http://www.example.com/referrer");
	}
	if (same_class_test(__LINE__, "Cookie", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap8 = static_cast<ValueMap*>(httprequest_test1.return_value("Cookie"));
		std::map<std::string, std::string> valuemap8;
		std::vector<std::string> keys8;
		valuemap8["session_id"] = "12345";
		valuemap8["user"] = "JohnDoe";
		keys8.push_back("session_id");
		keys8.push_back("user");
		check( valmap8->get_value_map(), valuemap8, keys8);
	}
	//Authorization
	// if (same_class_test(__LINE__, "Authorization", httprequest_test1) == true)
	// {
	// 	//map型
	// 	ValueSet* val = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
	// 	check( val->get_value_set(), "http://www.example.com/referrer");
	// }
	// if (same_class_test(__LINE__, "Cache-Control", httprequest_test1) == true)
	// {
	// 	//map型
	// 	ValueSet* val = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
	// 	check( val->get_value_set(), "http://www.example.com/referrer");
	// }//未実装
	// if (same_class_test(__LINE__, "Pragma", httprequest_test1) == true)
	// {
	// 	ValueSet* val = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
	// 	check( val->get_value_set(), "http://www.example.com/referrer");
	// }//未実装
	// if (same_class_test(__LINE__, "DNT", httprequest_test1) == true)
	// {
	// 	ValueSet* val = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
	// 	check( val->get_value_set(), "http://www.example.com/referrer");
	// }//未実装
	if (same_class_test(__LINE__, "Upgrade-Insecure-Requests", httprequest_test1) == true)
	{
		ValueSet* val9 = static_cast<ValueSet*>(httprequest_test1.return_value("Upgrade-Insecure-Requests"));
		check( val9->get_value_set(), "http://www.example.com/referrer");
	}
}

//g++ *.cpp ../HandleString/HandlingString.cpp