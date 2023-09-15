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

void	check(std::vector<std::string> target_vector, std::vector<std::string> subject_vector, size_t raw)
{
	std::vector<std::string>::iterator itr_now = target_vector.begin();
	while (itr_now != target_vector.end())
	{
		if (std::find(subject_vector.begin(), subject_vector.end(), *itr_now) == subject_vector.end())
		{
			std::cout << *itr_now << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, raw);
		}
		itr_now++;
	}
}

void	check(ValueDateSet *targetdatevalue, std::string day_name, std::string day, std::string month, std::string year, std::string hour, std::string minute, std::string second)
{
	EXPECT_EQ(targetdatevalue->get_valuedateset_day_name(), day_name);
	EXPECT_EQ(targetdatevalue->get_valuedateset_day(), day);
	EXPECT_EQ(targetdatevalue->get_valuedateset_month(), month);
	EXPECT_EQ(targetdatevalue->get_valuedateset_year(), year);
	EXPECT_EQ(targetdatevalue->get_valuedateset_hour(), hour);
	EXPECT_EQ(targetdatevalue->get_valuedateset_minute(), minute);
	EXPECT_EQ(targetdatevalue->get_valuedateset_second(), second);
}

//valuemap1.get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1
void	check(std::string only_value, std::map<std::string, std::string> target_wordmap, std::string expect_only_value, std::map<std::string, std::string> expected_wordmap, std::vector<std::string> keys)
{
	EXPECT_EQ(only_value, expect_only_value);
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
	if (same_class_test(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
		check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	}
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		ValueSet* val2 = static_cast<ValueSet*>(httprequest_test1.return_value("User-Agent"));
		check( val2->get_value_set(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "Accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray3 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept"));
		std::map<std::string, double> keyvalue3;
		std::vector<std::string> keys3;
		keyvalue3["text/html"] = 1.0;
		keyvalue3["application/xhtml+xml"] = 1.0;
		keyvalue3["application/xml"] = 0.9;
		keyvalue3["*/*"] = 0.8;
		keys3.push_back("text/html");
		keys3.push_back("application/xhtml+xml");
		keys3.push_back("application/xml");
		keys3.push_back("*/*");
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
		keyvalue5["deflate"] = 1.0;
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
		check( val9->get_value_set(), "1");
	}
}

// g++ *.cpp ../HandleString/HandlingString.cpp

// GET /path/to/resource HTTP/1.1
// X-Forwarded-For: 192.168.1.1
// X-Request-ID: 12345
// X-Requested-With: XMLHttpRequest
// If-None-Match: "some_etag"
// If-Modified-Since: Thu, 01 Sep 2023 12:00:00 GMT
// Max-Forwards: 10
// TE: trailers, deflate;q=0.5
// From: sender@example.com
// Origin: http://www.origin-example.com
// Via: 1.0 proxy.example.com (Apache/1.1)
// Age: 3600
// Warning: 199 Miscellaneous warning
// Access-Control-Allow-Origin: *
// X-Frame-Options: SAMEORIGIN

TEST(Request, TEST3)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\nX-Forwarded-For: 192.168.1.1\r\nX-Request-ID: 12345\r\nX-Requested-With: XMLHttpRequest\r\nIf-None-Match: some_etag\r\nIf-Modified-Since: Thu, 01 Sep 2023 12:00:00 GMT\r\nMax-Forwards: 10\r\nTE: trailers, deflate;q=0.5\r\nFrom: sender@example.com\r\nOrigin: http://www.origin-example.com\r\nVia: 1.0 proxy.example.com (Apache/1.1)\r\nAge: 3600\r\nWarning: 199 Miscellaneous warning\r\nAccess-Control-Allow-Origin: *\r\nX-Frame-Options: SAMEORIGIN\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	// if (same_class_test(__LINE__, "X-Forwarded-For", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
	// if (same_class_test(__LINE__, "X-Forwarded-For", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
	// if (same_class_test(__LINE__, "X-Request-ID", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
	// if (same_class_test(__LINE__, "X-Requested-With", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
	if (same_class_test(__LINE__, "If-None-Match", httprequest_test1) == true)
	{
		ValueArraySet* val1 = static_cast<ValueArraySet*>(httprequest_test1.return_value("If-None-Match"));
		std::vector<std::string> vector1;
		vector1.push_back("some_etag");
		check(val1->get_value_array(), vector1, 310);
	}
	if (same_class_test(__LINE__, "If-Modified-Since", httprequest_test1) == true)
	{
		ValueDateSet *dateval2 = static_cast<ValueDateSet*>(httprequest_test1.return_value("If-Modified-Since"));
		check(dateval2, "Thu", "01", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "Max-Forwards", httprequest_test1) == true)
	{
		ValueSet* val3 = static_cast<ValueSet*>(httprequest_test1.return_value("Max-Forwards"));
		check(val3->get_value_set(), "10");
	}
	if (same_class_test(__LINE__, "TE", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset4 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("TE"));
		std::map<std::string, double> keyvalue4;
		std::vector<std::string> keys4;
		keyvalue4["trailers"] = 1.0;
		keyvalue4["deflate"] = 0.5;
		keys4.push_back("trailers");
		keys4.push_back("deflate");
		check(valweightarrayset4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "From", httprequest_test1) == true)
	{
		ValueSet* val5 = static_cast<ValueSet*>(httprequest_test1.return_value("From"));
		check(val5->get_value_set(), "sender@example.com");
	}
	if (same_class_test(__LINE__, "Origin", httprequest_test1) == true)
	{
		ValueSet* val6 = static_cast<ValueSet*>(httprequest_test1.return_value("Origin"));
		check(val6->get_value_set(), "http://www.origin-example.com");
	}
	if (same_class_test(__LINE__, "Via", httprequest_test1) == true)
	{
		ValueSet* val7 = static_cast<ValueSet*>(httprequest_test1.return_value("Via"));
		check(val7->get_value_set(), "1.0 proxy.example.com (Apache/1.1)");
	}
	if (same_class_test(__LINE__, "Age", httprequest_test1) == true)
	{
		ValueSet* val8 = static_cast<ValueSet*>(httprequest_test1.return_value("Age"));
		check(val8->get_value_set(), "3600");
	}
	// if (same_class_test(__LINE__, "Warning", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Warning"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
	if (same_class_test(__LINE__, "Access-Control-Allow-Origin", httprequest_test1) == true)
	{
		ValueSet* val9 = static_cast<ValueSet*>(httprequest_test1.return_value("Access-Control-Allow-Origin"));
		check(val9->get_value_set(), "*");
	}
	// if (same_class_test(__LINE__, "X-Frame-Options", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Host"));
	// 	check( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	// }
}

// GET /example HTTP/1.1
// Host: example.com
// Accept-CH: viewport-width, width, downlink
// Accept-Charset: utf-8
// Accept-Post: text/html, application/json
// Accept-Ranges: bytes
// Access-Control-Allow-Credentials: true
// Access-Control-Allow-Headers: Content-Type, Authorization
// Access-Control-Allow-Methods: GET, POST, PUT, DELETE

TEST(Request, TEST4)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nHost: example.com\r\nAccept-CH: viewport-width, width, downlink\r\nAccept-Charset: utf-8\r\nAccept-Post: text/html, application/json\r\nAccept-Ranges: bytes\r\nAccess-Control-Allow-Credentials: true\r\nAccess-Control-Allow-Headers: Content-Type, Authorization\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/example");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Accept-CH", httprequest_test1) == true)
	{
		ValueArraySet* val1 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Accept-CH"));
		std::vector<std::string> vector1;
		vector1.push_back("viewport-width");
		vector1.push_back("width");
		vector1.push_back("downlink");
		check(val1->get_value_array(), vector1, 394);
	}
	if (same_class_test(__LINE__, "Accept-Charset", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset2 = static_cast<ValueWeightArraySet*>(httprequest_test1.return_value("Accept-Charset"));
		std::map<std::string, double> keyvalue2;
		std::vector<std::string> keys2;
		keyvalue2["utf-8"] = 1.0;
		keys2.push_back("utf-8");
		check(valweightarrayset2->get_valueweight_set(), keyvalue2, keys2);
	}
	if (same_class_test(__LINE__, "Accept-Post", httprequest_test1) == true)
	{
		TwoValueSet* twoval3 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Accept-Post"));
		check( twoval3->get_firstvalue(), twoval3->get_secondvalue(), "text/html", "application/json");
	}
	if (same_class_test(__LINE__, "Accept-Ranges", httprequest_test1) == true)
	{
		ValueSet* val4 = static_cast<ValueSet*>(httprequest_test1.return_value("Accept-Ranges"));
		check(val4->get_value_set(), "bytes");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Credentials", httprequest_test1) == true)
	{
		ValueSet* val5 = static_cast<ValueSet*>(httprequest_test1.return_value("Access-Control-Allow-Credentials"));
		check(val5->get_value_set(), "true");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Headers", httprequest_test1) == true)
	{
		ValueArraySet* val6 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Access-Control-Allow-Headers"));
		std::vector<std::string> vector6;
		vector6.push_back("Content-Type");
		vector6.push_back("Authorization");
		check(val6->get_value_array(), vector6, 426);
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Methods", httprequest_test1) == true)
	{
		ValueArraySet* val7 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Access-Control-Allow-Methods"));
		std::vector<std::string> vector7;
		// GET, POST, PUT, DELETE
		vector7.push_back("GET");
		vector7.push_back("POST");
		vector7.push_back("PUT");
		vector7.push_back("DELETE");
		check(val7->get_value_array(), vector7, 426);
	}
}

// OPTIONS /example HTTP/1.1
// Host: example.com
// Access-Control-Expose-Headers: X-Custom-Header, Content-Type
// Access-Control-Max-Age: 3600
// Access-Control-Request-Headers: Authorization, Content-Type
// Access-Control-Request-Method: POST
// Allow: GET, POST, PUT, DELETE
// Alt-Svc: h2="https://example.com:443"
// Alt-Used: h2
// Clear-Site-Data: "cache", "cookies"

TEST(Request, TEST5)
{
	const std::string TEST_REQUEST2 = "OPTIONS /example HTTP/1.1\r\nHost: example.com\r\nAccess-Control-Expose-Headers: X-Custom-Header, Content-Type\r\nAccess-Control-Max-Age: 3600\r\nAccess-Control-Request-Headers: Authorization, Content-Type\r\nAccess-Control-Request-Method: POST\r\nAllow: GET, POST, PUT, DELETE\r\nAlt-Svc: h2=\"https://example.com:443\"\r\nAlt-Used: h2\r\nClear-Site-Data: \"cache\", \"cookies\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "OPTIONS");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/example");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Access-Control-Expose-Headers", httprequest_test1) == true)
	{
		ValueArraySet* val1 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Access-Control-Expose-Headers"));
		std::vector<std::string> vector1;
		vector1.push_back("X-Custom-Header");
		vector1.push_back("Content-Type");
		check(val1->get_value_array(), vector1, 465);
	}
	if (same_class_test(__LINE__, "Access-Control-Max-Age", httprequest_test1) == true)
	{
		ValueSet* val2 = static_cast<ValueSet*>(httprequest_test1.return_value("Access-Control-Max-Age"));
		check(val2->get_value_set(), "3600");
	}
	if (same_class_test(__LINE__, "Access-Control-Request-Headers", httprequest_test1) == true)
	{
		ValueArraySet* val3 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Access-Control-Request-Headers"));
		std::vector<std::string> vector3;
		vector3.push_back("Authorization");
		vector3.push_back("Content-Type");
		check(val3->get_value_array(), vector3, 478);
	}
	if (same_class_test(__LINE__, "Access-Control-Request-Method", httprequest_test1) == true)
	{
		ValueSet* val4 = static_cast<ValueSet*>(httprequest_test1.return_value("Access-Control-Request-Method"));
		check(val4->get_value_set(), "POST");
	}
	if (same_class_test(__LINE__, "Allow", httprequest_test1) == true)
	{
		ValueArraySet* val5 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Allow"));
		std::vector<std::string> vector5;
		vector5.push_back("GET");
		vector5.push_back("POST");
		vector5.push_back("PUT");
		vector5.push_back("DELETE");
		check(val5->get_value_array(), vector5, 478);
	}
	if (same_class_test(__LINE__, "Alt-Svc", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap6 = static_cast<ValueMap*>(httprequest_test1.return_value("Alt-Svc"));
		std::map<std::string, std::string> valuemap6;
		std::vector<std::string> keys6;
		valuemap6["h2"] = "\"https://example.com:443\"";
		keys6.push_back("h2");
		check( valmap6->get_value_map(), valuemap6, keys6);
	}
	if (same_class_test(__LINE__, "Clear-Site-Data", httprequest_test1) == true)
	{
		ValueArraySet* val7 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Clear-Site-Data"));
		std::vector<std::string> vector7;
		vector7.push_back("\"cache\"");
		vector7.push_back("\"cookies\"");
		check(val7->get_value_array(), vector7, 511);
	}
}

// GET /example HTTP/1.1
// Host: example.com
// Content-Disposition: attachment; filename="example.txt"
// Content-Encoding: gzip
// Content-Language: en-US
// Content-Length: 1024
// Content-Location: /documents/example.txt
// Content-Range: bytes 0-511/1024
// Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
// Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp-report
// Content-Type: application/json

TEST(Request, TEST6)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nHost: example.com\r\nContent-Disposition: attachment; filename=\"example.txt\"\r\nContent-Encoding: gzip\r\nContent-Language: en-US\r\nContent-Length: 1024\r\nContent-Location: /documents/example.txt\r\nContent-Range: bytes 0-511/1024\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\r\nContent-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp-report\r\nContent-Type: application/json\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/example");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Content-Disposition", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap1 = static_cast<ValueMap*>(httprequest_test1.return_value("Content-Disposition"));
		std::map<std::string, std::string> valuemap1;
		std::vector<std::string> keys1;
		valuemap1["filename"] = "\"example.txt\"";
		keys1.push_back("filename");
		check( valmap1->get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1);
	}
	if (same_class_test(__LINE__, "Content-Encoding", httprequest_test1) == true)
	{
		ValueArraySet* val2 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Content-Encoding"));
		std::vector<std::string> vector2;
		vector2.push_back("gzip");
		check(val2->get_value_array(), vector2, 571);
	}
	if (same_class_test(__LINE__, "Content-Language", httprequest_test1) == true)
	{
		ValueArraySet* val3 = static_cast<ValueArraySet*>(httprequest_test1.return_value("Content-Language"));
		std::vector<std::string> vector3;
		vector3.push_back("en-US");
		check(val3->get_value_array(), vector3, 578);
	}
	if (same_class_test(__LINE__, "Content-Length", httprequest_test1) == true)
	{
		ValueSet* val4 = static_cast<ValueSet*>(httprequest_test1.return_value("Content-Length"));
		check(val4->get_value_set(), "1024");
	}
	if (same_class_test(__LINE__, "Content-Location", httprequest_test1) == true)
	{
		ValueSet* val5 = static_cast<ValueSet*>(httprequest_test1.return_value("Content-Location"));
		check(val5->get_value_set(), "/documents/example.txt");
	}
	if (same_class_test(__LINE__, "Content-Range", httprequest_test1) == true)
	{
		ValueSet* val6 = static_cast<ValueSet*>(httprequest_test1.return_value("Content-Range"));
		check(val6->get_value_set(), "bytes 0-511/1024");
	}
	// if (same_class_test(__LINE__, "Content-Security-Policy", httprequest_test1) == true)
	// {
	// 	TwoValueSet* twoval7 = static_cast<TwoValueSet*>(httprequest_test1.return_value("Content-Security-Policy"));
	// 	check( twoval7->get_firstvalue(), twoval7->get_secondvalue(), "default-src \'self\'", "script-src \'self\' \'unsafe-inline\'");
	// }
	if (same_class_test(__LINE__, "Content-Type", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap8 = static_cast<ValueMap*>(httprequest_test1.return_value("Content-Type"));
		EXPECT_EQ(valmap8->get_only_value(), "application/json");
	}
}

// GET /example HTTP/1.1\r\n
// Host: example.com\r\n
// Cross-Origin-Embedder-Policy: require-corp\r\n
// Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n
// Cross-Origin-Resource-Policy: same-origin\r\n
// Date: Thu, 15 Sep 2023 12:00:00 GMT\r\n
// Expect: 100-continue\r\n
// Expires: Thu, 15 Sep 2023 13:00:00 GMT\r\n
// Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\n
// Host: example.com\r\n
// If-Match: \"etag123\"\r\n
// If-Range: \"etag123\"\r\n
// If-Unmodified-Since: Thu, 15 Sep 2023 11:30:00 GMT\r\n
// Keep-Alive: timeout=5, max=1000\r\n
// Last-Modified: Thu, 15 Sep 2023 11:45:00 GMT\r\n
// Link: <https://example.com/style.css>; rel=preload; as=style\r\n
// Location: https://example.com/redirected-page\r\n

TEST(Request, TEST7)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nHost: example.com\r\nCross-Origin-Embedder-Policy: require-corp\r\nCross-Origin-Opener-Policy: same-origin-allow-popups\r\nCross-Origin-Resource-Policy: same-origin\r\nDate: Thu, 15 Sep 2023 12:00:00 GMT\r\nExpect: 100-continue\r\nExpires: Thu, 15 Sep 2023 13:00:00 GMT\r\nForwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\nHost: example.com\r\nIf-Match: \"etag123\"\r\nIf-Range: \"etag123\"\r\nIf-Unmodified-Since: Thu, 15 Sep 2023 11:30:00 GMT\r\nKeep-Alive: timeout=5, max=1000\r\nLast-Modified: Thu, 15 Sep 2023 11:45:00 GMT\r\nLink: <https://example.com/style.css>; rel=preload; as=style\r\nLocation: https://example.com/redirected-page\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_requestline().get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_requestline().get_target_page(), "/example");
	EXPECT_EQ(httprequest_test1.get_requestline().get_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "Cross-Origin-Embedder-Policy", httprequest_test1) == true)
	{
		ValueSet* val1 = static_cast<ValueSet*>(httprequest_test1.return_value("Cross-Origin-Embedder-Policy"));
		check(val1->get_value_set(), "require-corp");
	}
	if (same_class_test(__LINE__, "Cross-Origin-Opener-Policy", httprequest_test1) == true)
	{
		ValueSet* val2 = static_cast<ValueSet*>(httprequest_test1.return_value("Cross-Origin-Opener-Policy"));
		check(val2->get_value_set(), "same-origin-allow-popups");
	}
	if (same_class_test(__LINE__, "Cross-Origin-Resource-Policy", httprequest_test1) == true)
	{
		ValueSet* val3 = static_cast<ValueSet*>(httprequest_test1.return_value("Cross-Origin-Resource-Policy"));
		check(val3->get_value_set(), "same-origin");
	}
	if (same_class_test(__LINE__, "Date", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 12:00:00 GMT
		ValueDateSet *dateval4 = static_cast<ValueDateSet*>(httprequest_test1.return_value("Date"));
		check(dateval4, "Thu", "15", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "Expect", httprequest_test1) == true)
	{
		ValueSet* val5 = static_cast<ValueSet*>(httprequest_test1.return_value("Expect"));
		check(val5->get_value_set(), "100-continue");
	}
	if (same_class_test(__LINE__, "Expires", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 12:00:00 GMT
		ValueDateSet *dateval6 = static_cast<ValueDateSet*>(httprequest_test1.return_value("Expires"));
		check(dateval6, "Thu", "15", "Sep", "2023", "13", "00", "00");
	}
	if (same_class_test(__LINE__, "Forwarded", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap7 = static_cast<ValueMap*>(httprequest_test1.return_value("Forwarded"));
		std::map<std::string, std::string> valuemap7;
		std::vector<std::string> keys7;
		valuemap7["for"] = "192.0.2.60";
		valuemap7["proto"] = "http";
		valuemap7["by"] = "203.0.113.43";
		keys7.push_back("for");
		keys7.push_back("proto");
		keys7.push_back("by");
		check(valmap7->get_value_map(), valuemap7, keys7);
	}
	if (same_class_test(__LINE__, "If-Match", httprequest_test1) == true)
	{
		ValueArraySet* val8 = static_cast<ValueArraySet*>(httprequest_test1.return_value("If-Match"));
		std::vector<std::string> vector8;
		vector8.push_back("\"etag123\"");
		check(val8->get_value_array(), vector8, 685);
	}
	if (same_class_test(__LINE__, "If-Range", httprequest_test1) == true)
	{
		ValueArraySet* val9 = static_cast<ValueArraySet*>(httprequest_test1.return_value("If-Range"));
		std::vector<std::string> vector9;
		vector9.push_back("\"etag123\"");
		check(val9->get_value_array(), vector9, 692);
	}
	if (same_class_test(__LINE__, "If-Unmodified-Since", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:30:00 GMT
		ValueDateSet *dateval10 = static_cast<ValueDateSet*>(httprequest_test1.return_value("If-Unmodified-Since"));
		check(dateval10, "Thu", "15", "Sep", "2023", "11", "30", "00");
	}
	if (same_class_test(__LINE__, "Keep-Alive", httprequest_test1) == true)
	{
		//map型
		ValueMap* valmap11 = static_cast<ValueMap*>(httprequest_test1.return_value("Keep-Alive"));
		std::map<std::string, std::string> valuemap11;
		std::vector<std::string> keys11;
		valuemap11["timeout"] = "5";
		valuemap11["max"] = "1000";
		keys11.push_back("timeout");
		keys11.push_back("max");
		check(valmap11->get_value_map(), valuemap11, keys11);
	}
	if (same_class_test(__LINE__, "Last-Modified", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:45:00 GMT
		ValueDateSet *dateval12 = static_cast<ValueDateSet*>(httprequest_test1.return_value("Last-Modified"));
		check(dateval12, "Thu", "15", "Sep", "2023", "11", "45", "00");
	}
	if (same_class_test(__LINE__, "Location", httprequest_test1) == true)
	{
		ValueSet* val13 = static_cast<ValueSet*>(httprequest_test1.return_value("Location"));
		check(val13->get_value_set(), "https://example.com/redirected-page");
	}
}
