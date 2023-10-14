#include <string>
#include <algorithm>

#include "gtest/gtest.h"
#include "Constant.hpp"
#include "Color.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpRequest.hpp"
#include "RequestLine.hpp"
#include "Result.hpp"
#include "StringHandler.hpp"
#include "TwoValueSet.hpp"
#include "MultiFieldValues.hpp"
#include "Date.hpp"
#include "FieldValueMap.hpp"
#include "SingleFieldValue.hpp"
#include "ValueWeightArraySet.hpp"

////////////////////////////////////////////////////////////////////////////////
/* add */

TEST(TestHttpRequest, NgCaseRequestOnly) {
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n";
	HttpRequest request(TEST_REQUEST);

	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestHttpRequest, NgInvalidMethod) {
	const std::string TEST_REQUEST = "get /index.html HTTP/1.1\r\n"
									 "\r\n";
	HttpRequest request(TEST_REQUEST);

	EXPECT_EQ("get", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestHttpRequest, NgNoHeaders) {
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "\r\n";
	HttpRequest request(TEST_REQUEST);

	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestHttpRequest, NgInvalidHeaderFormat1) {
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Host: www.example.com\r";
	HttpRequest request(TEST_REQUEST);

	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}

TEST(TestHttpRequest, NgInvalidHeaderFormat2) {
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "\r\n"
									 "Host: www.example.com\r\n"
									 "\r\n";
	HttpRequest request(TEST_REQUEST);

	EXPECT_EQ("GET", request.get_method());
	EXPECT_EQ("/index.html", request.get_request_target());
	EXPECT_EQ("HTTP/1.1", request.get_http_version());
	EXPECT_EQ(STATUS_BAD_REQUEST, request.get_status_code());
}


////////////////////////////////////////////////////////////////////////////////

void	compare_inputvalue_truevalue_linkclass(std::map<std::string,
											   std::map<std::string, std::string> > test_map_values,
											   std::map<std::string, std::map<std::string, std::string> > true_map_values, size_t line)
{
	std::map<std::string, std::map<std::string, std::string> >::iterator true_itr_now = true_map_values.begin();
	std::map<std::string, std::string>	checking_map;
	std::map<std::string, std::string>	true_map;
	while (true_itr_now != true_map_values.end())
	{
		if (test_map_values.find(true_itr_now->first) == test_map_values.end())
			ADD_FAILURE_AT(__FILE__, line);
		else
		{
			checking_map = test_map_values[true_itr_now->first];
			true_map = true_map_values[true_itr_now->first];
			std::map<std::string, std::string>::iterator true_map_itr_now = true_map.begin();
			while (true_map_itr_now != true_map.end())
			{
				if (checking_map.find(true_map_itr_now->first) == true_map.end())
				{
					std::cout << true_map_itr_now->first << " is not exist" << std::endl;
					ADD_FAILURE_AT(__FILE__, line);
				}
				else
					EXPECT_EQ(checking_map[true_map_itr_now->first], true_map[true_map_itr_now->first]);
				true_map_itr_now++;
			}
		}
		true_itr_now++;
	}
}

void	compare_vectors_report(std::set<std::string> target_vector,
							   std::set<std::string> subject_vector, size_t line)
{
	std::set<std::string>::iterator itr_now = target_vector.begin();
	while (itr_now != target_vector.end())
	{
		if (subject_vector.find(*itr_now) == subject_vector.end())
		{
			std::cout << *itr_now << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, line);
		}
		itr_now++;
	}
}

void	compare_map_report(std::map<std::string, std::set<std::string> > target_map,
						   std::map<std::string, std::set<std::string> > true_map, size_t line)
{
	std::map<std::string, std::set<std::string> >::iterator itr_now = true_map.begin();
	while (itr_now != true_map.end())
	{
		if (target_map.find(itr_now->first) == target_map.end())
			ADD_FAILURE_AT(__FILE__, line);
		else
			compare_vectors_report(target_map[itr_now->first], true_map[itr_now->first], line);
		itr_now++;
	}
}

void	compare_daymap_report(Date *targetdatevalue, std::string day_name, std::string day, std::string month, std::string year, std::string hour, std::string minute, std::string second)
{
	EXPECT_EQ(targetdatevalue->get_day_name(), day_name);
	EXPECT_EQ(targetdatevalue->get_day(), day);
	EXPECT_EQ(targetdatevalue->get_month(), month);
	EXPECT_EQ(targetdatevalue->get_year(), year);
	EXPECT_EQ(targetdatevalue->get_hour(), hour);
	EXPECT_EQ(targetdatevalue->get_minute(), minute);
	EXPECT_EQ(targetdatevalue->get_second(), second);
}

//valuemap1.get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1
void	compair_valuemapset_withfirstvalue_report(std::string only_value,
												  std::map<std::string, std::string> target_wordmap,
												  std::string expect_only_value,
												  std::map<std::string, std::string> expected_wordmap,
												  std::set<std::string> keys)
{
	EXPECT_EQ(only_value, expect_only_value);
	std::set<std::string>::iterator itr_now = keys.begin();
	while (itr_now != keys.end())
	{
		std::map<std::string, std::string>::iterator key_is_itr = target_wordmap.begin();
		while (key_is_itr != target_wordmap.end())
		{
			if (key_is_itr->first == *itr_now)
				break;
			key_is_itr++;
		}
		if (key_is_itr == target_wordmap.end())
			ADD_FAILURE_AT(__FILE__, __LINE__);
		else
			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
		itr_now++;
	}
}

void	check(std::map<std::string, std::string> target_wordmap,
			  std::map<std::string, std::string> expected_wordmap,
			  std::set<std::string> keys)
{
	std::set<std::string>::iterator itr_now = keys.begin();
	while (itr_now != keys.end())
	{
		std::map<std::string, std::string>::iterator key_is_itr = target_wordmap.begin();
		while (key_is_itr != target_wordmap.end())
		{
			if (key_is_itr->first == *itr_now)
				break;
			key_is_itr++;
		}
		if (key_is_itr == target_wordmap.end())
		{
			std::cout << *itr_now << " is not exist" << std::endl;
			ADD_FAILURE_AT(__FILE__, __LINE__);
		}
		else
			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
		itr_now++;
	}
}

void	compair_valueweightarray_report(std::map<std::string, double> target_wordmap,
										std::map<std::string, double> expected_wordmap,
										std::set<std::string> keys)
{
	std::set<std::string>::iterator itr_now = keys.begin();
	while (itr_now != keys.end())
	{
		std::map<std::string, double>::iterator key_is_itr = target_wordmap.begin();
		while (key_is_itr != target_wordmap.end())
		{
			if (key_is_itr->first == *itr_now)
				break;
			key_is_itr++;
		}
		if (key_is_itr == target_wordmap.end())
			ADD_FAILURE_AT(__FILE__, __LINE__);
		else
			EXPECT_EQ(target_wordmap[*itr_now], expected_wordmap[*itr_now]);
		itr_now++;
	}
}

void	compair_twovaluemap_report(const std::string &first_target_word, const std::string &second_target_word, const std::string &exp_1, const std::string &exp_2)
{
	EXPECT_EQ(first_target_word, exp_1);
	EXPECT_EQ(second_target_word, exp_2);
}

void	compair_valueset_report(const std::string &target_word, const std::string &expected_word)
{
	EXPECT_EQ(target_word, expected_word);
}

bool	same_class_test(int line, const char *key, HttpRequest &target)
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

bool	keyword_doesnot_exist(int line, const char *key, HttpRequest &target)
{
	(void)line;
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
		return (false);
	}
	ADD_FAILURE_AT(__FILE__, line);
	return (true);
}

TEST(Request, SEGV)
{
    const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n\n\n\n";
    HttpRequest httprequest_test1(TEST_REQUEST);
    EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, UNCORRECTFORMATREQUESTLINE1)
{
	const std::string TEST_REQUEST = "GET/index.htmlHTTP/1.1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, UNCORRECTFORMATREQUESTLINE2)
{
	const std::string TEST_REQUEST = "GET /index.html\nHTTP/1.1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, REQUESTLINETEST1)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/index.html");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
}

TEST(Request, TEST1)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Host: www.example.com   \r\n"
									 "ETag: some_etag\r\n"
									 "User-Agent: YourUserAgent\r\n"
									 "Accept: text/html\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/index.html");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Host"));
		compair_twovaluemap_report( twoval->get_firstvalue(), twoval->get_secondvalue(), "www.example.com", "");
	}
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		SingleFieldValue* val = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"User-Agent"));
		compair_valueset_report( val->get_value(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "Accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept"));
		std::map<std::string, double> keyvalue;
		std::set<std::string> keys;
		keyvalue["text/html"] = 1.0;
		keys.insert("text/html");
		compair_valueweightarray_report(valweightarray->get_valueweight_set(), keyvalue, keys);
	}
}

TEST(Request, TOP_WARD_KORON)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 ": www.example.com\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, TEST1_CONTAIN_FORBIDDENWORD)
{
	const std::string TEST_REQUEST = "GET /index.html \rHTTP/1.1\r\n"
									 "Host: www.example.com\r\n"
									 "ETag: \3some_etag\r\n"
									 "User-Agent: \7YourUserAgent\r\n"
									 "Accept: text/html\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, NOT_CORRECTRY_FORMAT)
{
	const std::string TEST_REQUEST = "GET /index.html HTTP/1.1\r\n"
									 "Host: www.example.com\r\n"
									 "ETag : some_etag\r\n"
									 "User-Agent: YourUserAgent\r\n"
									 "Accept: text/html\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}


TEST(Request, TEST1_include_empty)
{
	const std::string TEST_REQUEST = "GET 	/index.html HTTP/1.1\r\n"
									 "Host: www.example  .com\r\n"
									 "ETag: some_etag\r\n"
									 "User-Agent: YourUser  Agent  \r\n"
									 "Accept: text  /html  \r\n";
	HttpRequest httprequest_test1(TEST_REQUEST);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, AcceptEncoding)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Encoding: gzip;q=0.5, deflate\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	if (same_class_test(__LINE__, "Accept-Encoding", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray5 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Encoding"));
		std::map<std::string, double> keyvalue5;
		std::set<std::string> keys5;
		keyvalue5["gzip"] = 0.5;
		keyvalue5["deflate"] = 1.0;
		keys5.insert("gzip");
		keys5.insert("deflate");
		compair_valueweightarray_report(valweightarray5->get_valueweight_set(), keyvalue5, keys5);
	}
}

TEST(Request, AcceptEncoding_Error1)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Encoding: gzip;;;;;;q=;0.5, deflate\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, AcceptEncoding_Error2)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Encoding: gzip;q=0.5, ,,def,l,ate\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
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
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "User-Agent: YourUserAgent\r\n"
									  "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
									  "Accept-Language: en-US,en;q=0.5\r\n"
									  "Accept-Encoding: gzip, deflate\r\n"
									  "Connection: keep-alive\r\n"
									  "Referer: http://www.example.com/referrer\r\n"
									  "Cookie: session_id=12345; user=JohnDoe\r\n"
									  "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
									  "Cache-Control: no-cache\r\n"
									  "Pragma: no-cache\r\n"
									  "DNT: 1\r\n"
									  "Upgrade-Insecure-Requests: 1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Host", httprequest_test1) == true)
	{
		TwoValueSet* twoval1 = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Host"));
		compair_twovaluemap_report( twoval1->get_firstvalue(), twoval1->get_secondvalue(), "example.com", "");
	}
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		SingleFieldValue* val2 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"User-Agent"));
		compair_valueset_report( val2->get_value(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "Accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray3 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept"));
		std::map<std::string, double> keyvalue3;
		std::set<std::string> keys3;
		keyvalue3["text/html"] = 1.0;
		keyvalue3["application/xhtml+xml"] = 1.0;
		keyvalue3["application/xml"] = 0.9;
		keyvalue3["*/*"] = 0.8;
		keys3.insert("text/html");
		keys3.insert("application/xhtml+xml");
		keys3.insert("application/xml");
		keys3.insert("*/*");
		compair_valueweightarray_report(valweightarray3->get_valueweight_set(), keyvalue3, keys3);
	}
	if (same_class_test(__LINE__, "Accept-Language", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Language"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["en-US"] = 1.0;
		keyvalue4["en"] = 0.5;
		keys4.insert("en-US");
		keys4.insert("en");
		compair_valueweightarray_report(valweightarray4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "Accept-Encoding", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray5 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Encoding"));
		std::map<std::string, double> keyvalue5;
		std::set<std::string> keys5;
		keyvalue5["gzip"] = 1.0;
		keyvalue5["deflate"] = 1.0;
		keys5.insert("gzip");
		keys5.insert("deflate");
		compair_valueweightarray_report(valweightarray5->get_valueweight_set(), keyvalue5, keys5);
	}
	if (same_class_test(__LINE__, "Connection", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Connection"));
		compair_valueset_report( val6->get_value(), "keep-alive");
	}
	if (same_class_test(__LINE__, "Referer", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Referer"));
		compair_valueset_report( val7->get_value(), "http://www.example.com/referrer");
	}
	if (same_class_test(__LINE__, "Cookie", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap8 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Cookie"));
		std::map<std::string, std::string> valuemap8;
		std::set<std::string> keys8;
		valuemap8["session_id"] = "12345";
		valuemap8["user"] = "JohnDoe";
		keys8.insert("session_id");
		keys8.insert("user");
		check( valmap8->get_value_map(), valuemap8, keys8);
	}
	//Authorization
	if (same_class_test(__LINE__, "Authorization", httprequest_test1) == true)
	{
		//map型 Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
		TwoValueSet* twoval9 = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Authorization"));
		compair_twovaluemap_report(twoval9->get_firstvalue(), twoval9->get_secondvalue(), "Basic", "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
	}
	if (same_class_test(__LINE__, "Upgrade-Insecure-Requests", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Upgrade-Insecure-Requests"));
		compair_valueset_report( val9->get_value(), "1");
	}
}

TEST(Request, TEST2ERROR1)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Language: en-US,en;;;;q=0.5\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, TEST2ANYCORON)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Language: en-US,en;q=0.5,,\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	if (same_class_test(__LINE__, "Accept-Language", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Language"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["en-US"] = 1.0;
		keyvalue4["en"] = 0.5;
		keys4.insert("en-US");
		keys4.insert("en");
		compair_valueweightarray_report(valweightarray4->get_valueweight_set(), keyvalue4, keys4);
	}
}

TEST(Request, TEST2NOWEIGHTSEMICORON)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Accept-Language: en-US,en;,,\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

TEST(Request, TEST2_include_empty)
{
	const std::string TEST_REQUEST2 = "GET 		/path/to/resource HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "User-Agent: YourUserAgent\r\n"
									  "Accept: text/ht   ml,application/xhtml+xml,appl  ication/xml;q=0.9,*/*;q=0.8\r\n"
									  "Accept-Language: en -US,en;q=0.5\r\n"
									  "Accept-Encoding: gzi p, deflate\r\n"
									  "Connection: keep- alive\r\n"
									  "Referer: http://www.exampl e.com/referrer\r\n"
									  "Cookie: session _id=12345;  user=JohnDoe\r\n"
									  "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
									  "Cache-Control: no-cache\r\n"
									  "Pragma: no-cache\r\n"
									  "DNT: 1\r\n"
									  "Upgrade-Insecure-Requests: 1\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_status_code(), 400);
}

// g++ *.cpp ../HandleString/StringHandler.cpp

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
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "X-Forwarded-For: 192.168.1.1\r\n"
									  "X-Request-ID: 12345\r\n"
									  "X-Requested-With: XMLHttpRequest\r\n"
									  "If-None-Match: some_etag\r\n"
									  "If-Modified-Since: Thu, 01 Sep 2023 12:00:00 GMT\r\n"
									  "Max-Forwards: 10\r\n"
									  "TE: trailers, deflate;q=0.5\r\n"
									  "From: sender@example.com\r\n"
									  "Origin: http://www.origin-example.com\r\n"
									  "Via: 1.0 proxy.example.com (Apache/1.1)\r\n"
									  "Age: 3600\r\n"
									  "Warning: 199 Miscellaneous warning\r\n"
									  "Access-Control-Allow-Origin: *\r\n"
									  "X-Frame-Options: SAMEORIGIN\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "If-None-Match", httprequest_test1) == true)
	{
		MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"If-None-Match"));
		std::set<std::string> vector1;
		vector1.insert("some_etag");
		compare_vectors_report(val1->get_values(), vector1, __LINE__);
	}
	if (same_class_test(__LINE__, "If-Modified-Since", httprequest_test1) == true)
	{
		Date *dateval2 = static_cast<Date*>(httprequest_test1.get_field_values(
				"If-Modified-Since"));
		compare_daymap_report(dateval2, "Thu", "01", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "Max-Forwards", httprequest_test1) == true)
	{
		SingleFieldValue* val3 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Max-Forwards"));
		compair_valueset_report(val3->get_value(), "10");
	}
	if (same_class_test(__LINE__, "TE", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"TE"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["trailers"] = 1.0;
		keyvalue4["deflate"] = 0.5;
		keys4.insert("trailers");
		keys4.insert("deflate");
		compair_valueweightarray_report(valweightarrayset4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "From", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"From"));
		compair_valueset_report(val5->get_value(), "sender@example.com");
	}
	if (same_class_test(__LINE__, "Origin", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Origin"));
		compair_valueset_report(val6->get_value(), "http://www.origin-example.com");
	}
	if (same_class_test(__LINE__, "Via", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Via"));
		compair_valueset_report(val7->get_value(), "1.0 proxy.example.com (Apache/1.1)");
	}
	if (same_class_test(__LINE__, "Age", httprequest_test1) == true)
	{
		SingleFieldValue* val8 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Age"));
		compair_valueset_report(val8->get_value(), "3600");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Origin", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Origin"));
		compair_valueset_report(val9->get_value(), "*");
	}
}

TEST(Request, TEST3_include_empty)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "If-None-Match:  some  _etag\r\n"
									  "If-Modified-Since: Thu, 0 1 Sep 2023 12:00:00 GMT\r\n"
									  "Max-Forwards: 1    0\r\n"
									  "TE: trail ers, defla  te;q=0.5\r\n"
									  "From: sender@ example.com\r\n"
									  "Origin: http:// www.origin-example.com\r\n"
									  "Via: 1.0 proxy.example.com (Apache/1.1)\r\n"
									  "Age: 36  00\r\n"
									  "Warning: 199 Miscellaneous warning\r\n"
									  "Access-Control-Allow-Origin: *\r\n"
									  "X-Frame-Options: SAMEORIGIN\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "If-None-Match", httprequest_test1) == true)
	{
		MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"If-None-Match"));
		std::set<std::string> vector1;
		vector1.insert("some  _etag");
		compare_vectors_report(val1->get_values(), vector1, __LINE__);
	}
	keyword_doesnot_exist(__LINE__, "If-Modified-Since", httprequest_test1);
	keyword_doesnot_exist(__LINE__, "Max-Forwards", httprequest_test1);
	keyword_doesnot_exist(__LINE__, "TE", httprequest_test1);
	if (same_class_test(__LINE__, "From", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"From"));
		compair_valueset_report(val5->get_value(), "sender@ example.com");
	}
	if (same_class_test(__LINE__, "Origin", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Origin"));
		compair_valueset_report(val6->get_value(), "http:// www.origin-example.com");
	}
	if (same_class_test(__LINE__, "Via", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Via"));
		compair_valueset_report(val7->get_value(), "1.0 proxy.example.com (Apache/1.1)");
	}
	keyword_doesnot_exist(__LINE__, "Age", httprequest_test1);
	if (same_class_test(__LINE__, "Access-Control-Allow-Origin", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Origin"));
		compair_valueset_report(val9->get_value(), "*");
	}
}

TEST(Request, MAX_FORWARDS_TEST)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Max-Forwards: -1\r\n"
									  "Max-Forwards: 1000000000000000000\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	keyword_doesnot_exist(__LINE__, "Max-Forwards", httprequest_test1);
}

TEST(Request, AGE_MINUS)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "Age: -1\r\n"
									  "Age: 11111111111111\r\n"
									  "Age: -1";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	keyword_doesnot_exist(__LINE__, "Age", httprequest_test1);
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
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Accept-CH: viewport-width, width, downlink\r\n"
									  "Accept-Charset: utf-8\r\n"
									  "Accept-Post: text/html, application/json\r\n"
									  "Accept-Ranges: bytes\r\n"
									  "Access-Control-Allow-Credentials: true\r\n"
									  "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
									  "Access-Control-Allow-Methods: GET, POST, PUT, DELETE\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Accept-CH", httprequest_test1) == true)
	{
		MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Accept-CH"));
		std::set<std::string> vector1;
		vector1.insert("viewport-width");
		vector1.insert("width");
		vector1.insert("downlink");
		compare_vectors_report(val1->get_values(), vector1, 394);
	}
	if (same_class_test(__LINE__, "Accept-Charset", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset2 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Charset"));
		std::map<std::string, double> keyvalue2;
		std::set<std::string> keys2;
		keyvalue2["utf-8"] = 1.0;
		keys2.insert("utf-8");
		compair_valueweightarray_report(valweightarrayset2->get_valueweight_set(), keyvalue2, keys2);
	}
	if (same_class_test(__LINE__, "Accept-Post", httprequest_test1) == true)
	{
		TwoValueSet* twoval3 = static_cast<TwoValueSet*>(httprequest_test1.get_field_values(
				"Accept-Post"));
		compair_twovaluemap_report( twoval3->get_firstvalue(), twoval3->get_secondvalue(), "text/html", "application/json");
	}
	if (same_class_test(__LINE__, "Accept-Ranges", httprequest_test1) == true)
	{
		SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Accept-Ranges"));
		compair_valueset_report(val4->get_value(), "bytes");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Credentials", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Credentials"));
		compair_valueset_report(val5->get_value(), "true");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Headers", httprequest_test1) == true)
	{
		MultiFieldValues* val6 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Headers"));
		std::set<std::string> vector6;
		vector6.insert("Content-Type");
		vector6.insert("Authorization");
		compare_vectors_report(val6->get_values(), vector6, 492);
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Methods", httprequest_test1) == true)
	{
		MultiFieldValues* val7 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Methods"));
		std::set<std::string> vector7;
		// GET, POST, PUT, DELETE
		vector7.insert("GET");
		vector7.insert("POST");
		vector7.insert("PUT");
		vector7.insert("DELETE");
		compare_vectors_report(val7->get_values(), vector7, 503);
	}
}

TEST(Request, TEST4_include_empty)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Accept-CH: viewpor  t-width , wi dth  , downlink\r\n"
									  "Accept-Charset: utf-8  \r\n"
									  "Accept-Post: text/ html, application/json\r\n"
									  "Accept-Ranges: b ytes\r\n"
									  "Access-Control-Allow-Credentials: true\r\n"
									  "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
									  "Access-Control-Allow-Methods: G ET, POST, PUT, DELETE\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Accept-CH", httprequest_test1) == true)
	{
		MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Accept-CH"));
		std::set<std::string> vector1;
		vector1.insert("viewpor  t-width");
		vector1.insert("wi dth");
		vector1.insert("downlink");
		compare_vectors_report(val1->get_values(), vector1, 661);
	}
	if (same_class_test(__LINE__, "Accept-Charset", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset2 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"Accept-Charset"));
		std::map<std::string, double> keyvalue2;
		std::set<std::string> keys2;
		keyvalue2["utf-8"] = 1.0;
		keys2.insert("utf-8");
		compair_valueweightarray_report(valweightarrayset2->get_valueweight_set(), keyvalue2, keys2);
	}
	keyword_doesnot_exist(__LINE__, "Accept-Ranges", httprequest_test1);
	if (same_class_test(__LINE__, "Access-Control-Allow-Credentials", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Credentials"));
		compair_valueset_report(val5->get_value(), "true");
	}
	if (same_class_test(__LINE__, "Access-Control-Allow-Headers", httprequest_test1) == true)
	{
		MultiFieldValues* val6 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Access-Control-Allow-Headers"));
		std::set<std::string> vector6;
		vector6.insert("Content-Type");
		vector6.insert("Authorization");
		compare_vectors_report(val6->get_values(), vector6, 492);
	}
	keyword_doesnot_exist(__LINE__, "Access-Control-Allow-Methods", httprequest_test1);
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

// change OPTIONS -> GET, for request validate
TEST(Request, TEST5)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Access-Control-Expose-Headers: X-Custom-Header, Content-Type\r\n"
									  "Access-Control-Max-Age: 3600\r\n"
									  "Access-Control-Request-Headers: Authorization, Content-Type\r\n"
									  "Access-Control-Request-Method: POST\r\n"
									  "Allow: GET, POST, PUT, DELETE\r\n"
									  "Alt-Svc: h2=\"https://example.com:443\"\r\n"
									  "Alt-Used: h2\r\n"
									  "Clear-Site-Data: \"cache\", \"cookies\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Access-Control-Expose-Headers", httprequest_test1) == true)
	{
		MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Access-Control-Expose-Headers"));
		std::set<std::string> vector1;
		vector1.insert("X-Custom-Header");
		vector1.insert("Content-Type");
		compare_vectors_report(val1->get_values(), vector1, 779);
	}
	if (same_class_test(__LINE__, "Access-Control-Max-Age", httprequest_test1) == true)
	{
		SingleFieldValue* val2 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Max-Age"));
		compair_valueset_report(val2->get_value(), "3600");
	}
	if (same_class_test(__LINE__, "Access-Control-Request-Headers", httprequest_test1) == true)
	{
		MultiFieldValues* val3 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Access-Control-Request-Headers"));
		std::set<std::string> vector3;
		vector3.insert("Authorization");
		vector3.insert("Content-Type");
		compare_vectors_report(val3->get_values(), vector3, 478);
	}
	if (same_class_test(__LINE__, "Access-Control-Request-Method", httprequest_test1) == true)
	{
		SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Access-Control-Request-Method"));
		compair_valueset_report(val4->get_value(), "POST");
	}
	if (same_class_test(__LINE__, "Allow", httprequest_test1) == true)
	{
		MultiFieldValues* val5 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Allow"));
		std::set<std::string> vector5;
		vector5.insert("GET");
		vector5.insert("POST");
		vector5.insert("PUT");
		vector5.insert("DELETE");
		compare_vectors_report(val5->get_values(), vector5, 478);
	}
	if (same_class_test(__LINE__, "Alt-Svc", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap6 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Alt-Svc"));
		std::map<std::string, std::string> valuemap6;
		std::set<std::string> keys6;
		valuemap6["h2"] = "\"https://example.com:443\"";
		keys6.insert("h2");
		check( valmap6->get_value_map(), valuemap6, keys6);
	}
	if (same_class_test(__LINE__, "Clear-Site-Data", httprequest_test1) == true)
	{
		MultiFieldValues* val7 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Clear-Site-Data"));
		std::set<std::string> vector7;
		vector7.insert("\"cache\"");
		vector7.insert("\"cookies\"");
		compare_vectors_report(val7->get_values(), vector7, 511);
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
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Content-Disposition: attachment; filename=\"example.txt\"\r\n"
									  "Content-Encoding: gzip\r\n"
									  "Content-Language: en-US\r\n"
									  "Content-Length: 1024\r\n"
									  "Content-Location: /documents/example.txt\r\n"
									  "Content-Range: bytes 0-511/1024\r\n"
									  "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\r\n"
									  "Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp-report\r\n"
									  "Content-Type: application/json\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "Content-Disposition", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap1 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Content-Disposition"));
		std::map<std::string, std::string> valuemap1;
		std::set<std::string> keys1;
		valuemap1["filename"] = "\"example.txt\"";
		keys1.insert("filename");
		compair_valuemapset_withfirstvalue_report( valmap1->get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1);
	}
	if (same_class_test(__LINE__, "Content-Encoding", httprequest_test1) == true)
	{
		MultiFieldValues* val2 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Content-Encoding"));
		std::set<std::string> vector2;
		vector2.insert("gzip");
		compare_vectors_report(val2->get_values(), vector2, 571);
	}
	if (same_class_test(__LINE__, "Content-Language", httprequest_test1) == true)
	{
		MultiFieldValues* val3 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Content-Language"));
		std::set<std::string> vector3;
		vector3.insert("en-US");
		compare_vectors_report(val3->get_values(), vector3, 578);
	}
	if (same_class_test(__LINE__, "Content-Length", httprequest_test1) == true)
	{

		SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Content-Length"));
		compair_valueset_report(val4->get_value(), "1024");
	}
	if (same_class_test(__LINE__, "Content-Location", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Content-Location"));
		compair_valueset_report(val5->get_value(), "/documents/example.txt");
	}
	if (same_class_test(__LINE__, "Content-Range", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Content-Range"));
		compair_valueset_report(val6->get_value(), "bytes 0-511/1024");
	}
	// if (same_class_test(__LINE__, "Content-Security-Policy", httprequest_test1) == true)
	// {
	// 	SecurityPolicy* securitypolicy7 = static_cast<SecurityPolicy*>(httprequest_test1.get_field_values(
	// 			"Content-Security-Policy"));
	// 	std::map<std::string, std::set<std::string> >	policy_directive;
	// 	// default-src 'self'; script-src 'self' 'unsafe-inline'
	// 	std::set<std::string>	test_vector7_1;
	// 	std::set<std::string>	test_vector7_2;
	// 	test_vector7_1.insert("\'self\'");
	// 	test_vector7_2.insert("\'self\'");
	// 	test_vector7_2.insert("\'unsafe-inline\'");
	// 	policy_directive["default-src"] = test_vector7_1;
	// 	policy_directive["script-src"] = test_vector7_2;
	// 	compare_map_report(securitypolicy7->get_policy_directhive(), policy_directive, __LINE__);
	// }
	if (same_class_test(__LINE__, "Content-Type", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap8 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Content-Type"));
		EXPECT_EQ(valmap8->get_only_value(), "application/json");
	}
}

TEST(Request, TEST_CONTENT_LENGTH)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nContent-Length: -1\r\nContent-Length: 10000000000000000\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	keyword_doesnot_exist(__LINE__, "Content-Length", httprequest_test1);
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
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nCross-Origin-Embedder-Policy: require-corp\r\nCross-Origin-Opener-Policy: same-origin-allow-popups\r\nCross-Origin-Resource-Policy: same-origin\r\nDate: Thu, 15 Sep 2023 12:00:00 GMT\r\nExpect: 100-continue\r\nExpires: Thu, 15 Sep 2023 13:00:00 GMT\r\nForwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\nHost: example.com\r\nIf-Match: \"etag123\"\r\nIf-Range: \"etag123\"\r\nIf-Unmodified-Since: Thu, 15 Sep 2023 11:30:00 GMT\r\nKeep-Alive: timeout=5, max=1000\r\nLast-Modified: Thu, 15 Sep 2023 11:45:00 GMT\r\nLink: <https://example.com/style.css>; rel=preload; as=style\r\nLocation: https://example.com/redirected-page\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "Cross-Origin-Embedder-Policy", httprequest_test1) == true)
	{
		SingleFieldValue* val1 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Cross-Origin-Embedder-Policy"));
		compair_valueset_report(val1->get_value(), "require-corp");
	}
	if (same_class_test(__LINE__, "Cross-Origin-Opener-Policy", httprequest_test1) == true)
	{
		SingleFieldValue* val2 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Cross-Origin-Opener-Policy"));
		compair_valueset_report(val2->get_value(), "same-origin-allow-popups");
	}
	if (same_class_test(__LINE__, "Cross-Origin-Resource-Policy", httprequest_test1) == true)
	{
		SingleFieldValue* val3 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Cross-Origin-Resource-Policy"));
		compair_valueset_report(val3->get_value(), "same-origin");
	}
	if (same_class_test(__LINE__, "Date", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 12:00:00 GMT
		Date *dateval4 = static_cast<Date*>(httprequest_test1.get_field_values(
				"Date"));
		compare_daymap_report(dateval4, "Thu", "15", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "Expect", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Expect"));
		compair_valueset_report(val5->get_value(), "100-continue");
	}
	if (same_class_test(__LINE__, "Expires", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Expires"));
		compair_valueset_report(val6->get_value(), "Thu, 15 Sep 2023 13:00:00 GMT");
	}
	if (same_class_test(__LINE__, "Forwarded", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap7 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Forwarded"));
		std::map<std::string, std::string> valuemap7;
		std::set<std::string> keys7;
		valuemap7["for"] = "192.0.2.60";
		valuemap7["proto"] = "http";
		valuemap7["by"] = "203.0.113.43";
		keys7.insert("for");
		keys7.insert("proto");
		keys7.insert("by");
		check(valmap7->get_value_map(), valuemap7, keys7);
	}
	if (same_class_test(__LINE__, "If-Match", httprequest_test1) == true)
	{
		MultiFieldValues* val8 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"If-Match"));
		std::set<std::string> vector8;
		vector8.insert("\"etag123\"");
		compare_vectors_report(val8->get_values(), vector8, 685);
	}
	if (same_class_test(__LINE__, "If-Range", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"If-Range"));
		compair_valueset_report(val9->get_value(), "\"etag123\"");
	}
	if (same_class_test(__LINE__, "If-Unmodified-Since", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:30:00 GMT
		Date *dateval10 = static_cast<Date*>(httprequest_test1.get_field_values(
				"If-Unmodified-Since"));
		compare_daymap_report(dateval10, "Thu", "15", "Sep", "2023", "11", "30", "00");
	}
	if (same_class_test(__LINE__, "Keep-Alive", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap11 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Keep-Alive"));
		std::map<std::string, std::string> valuemap11;
		std::set<std::string> keys11;
		valuemap11["timeout"] = "5";
		valuemap11["max"] = "1000";
		keys11.insert("timeout");
		keys11.insert("max");
		check(valmap11->get_value_map(), valuemap11, keys11);
	}
	if (same_class_test(__LINE__, "Last-Modified", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:45:00 GMT
		Date *dateval12 = static_cast<Date*>(httprequest_test1.get_field_values(
				"Last-Modified"));
		compare_daymap_report(dateval12, "Thu", "15", "Sep", "2023", "11", "45", "00");
	}
	if (same_class_test(__LINE__, "Link", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:45:00 GMT
		// <https://example.com/style.css>; rel=preload; as=style\r\n
		std::map<std::string, std::map<std::string, std::string> > test_map_values;
		std::map<std::string, std::string>	map_value;
		map_value["rel"] = "preload";
		map_value["as"] = "style";
		test_map_values["<https://example.com/style.css>"] = map_value;
		LinkClass *linkckass12 = static_cast<LinkClass*>(httprequest_test1.get_field_values(
				"Link"));
		compare_inputvalue_truevalue_linkclass(linkckass12->get_link_valuemap(), test_map_values, __LINE__);
	}
	if (same_class_test(__LINE__, "Location", httprequest_test1) == true)
	{
		SingleFieldValue* val13 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Location"));
		compair_valueset_report(val13->get_value(), "https://example.com/redirected-page");
	}
}

// GET /example HTTP/1.1z\r\n
// Host: example.com\r\n
// Permissions-Policy: geolocation=(self "https://example.com"), camera=()\r\n
// Proxy-Authenticate: Basic realm="Proxy Server"\r\n
// Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n
// Referer: https://example.com/previous-page\r\n
// Retry-After: 120\r\n
// Sec-Fetch-Dest: document\r\n
// Sec-Fetch-Mode: navigate\r\n
// Sec-Fetch-Site: same-origin\r\n
// Sec-Fetch-User: ?1\r\n
// Sec-Purpose: prefetch\r\n
// Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n
// Server: Apache/2.4.41 (Ubuntu)\r\n

TEST(Request, TEST8)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nHost: example.com\r\nPermission-Policy: geolocation=(self \"https://example.com\"), camera=()\r\nProxy-Authenticate: Basic realm=\"Proxy Server\"\r\nProxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\nReferer: https://example.com/previous-page\r\nRetry-After: 120\r\nSec-Fetch-Dest: document\r\nSec-Fetch-Mode: navigate\r\nSec-Fetch-Site: same-origin\r\nSec-Fetch-User: ?1\r\nSec-Purpose: prefetch\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nServer: Apache/2.4.41 (Ubuntu)\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "Proxy-Authenticate", httprequest_test1) == true)
	{
		//map型
		FieldValueMap* valmap2 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values(
				"Proxy-Authenticate"));
		std::map<std::string, std::string> valuemap2;
		std::set<std::string> keys2;
		valuemap2["realm"] = "\"Proxy Server\"";
		keys2.insert("realm");
		check(valmap2->get_value_map(), valuemap2, keys2);
	}
	if (same_class_test(__LINE__, "Retry-After", httprequest_test1) == true)
	{
		SingleFieldValue* val3 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Retry-After"));
		compair_valueset_report(val3->get_value(), "120");
	}
	if (same_class_test(__LINE__, "Sec-Fetch-Dest", httprequest_test1) == true)
	{
		SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Fetch-Dest"));
		compair_valueset_report(val4->get_value(), "document");
	}
	if (same_class_test(__LINE__, "Sec-Fetch-Mode", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Fetch-Mode"));
		compair_valueset_report(val5->get_value(), "navigate");
	}
	if (same_class_test(__LINE__, "Sec-Fetch-Site", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Fetch-Site"));
		compair_valueset_report(val6->get_value(), "same-origin");
	}
	if (same_class_test(__LINE__, "Sec-Fetch-Site", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Fetch-Site"));
		compair_valueset_report(val7->get_value(), "same-origin");
	}
	if (same_class_test(__LINE__, "Sec-Fetch-User", httprequest_test1) == true)
	{
		SingleFieldValue* val8 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Fetch-User"));
		compair_valueset_report(val8->get_value(), "?1");
	}
	if (same_class_test(__LINE__, "Sec-Purpose", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-Purpose"));
		compair_valueset_report(val9->get_value(), "prefetch");
	}
	if (same_class_test(__LINE__, "Sec-WebSocket-Accept", httprequest_test1) == true)
	{
		SingleFieldValue* val10 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Sec-WebSocket-Accept"));
		compair_valueset_report(val10->get_value(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
	}
	if (same_class_test(__LINE__, "Server", httprequest_test1) == true)
	{
		SingleFieldValue* val11 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Server"));
		compair_valueset_report(val11->get_value(), "Apache/2.4.41 (Ubuntu)");
	}
}

// /GET /example HTTP/1.1\r\n
// Host: example.com\r\n
// Service-Worker-Navigation-Preload: true\r\n
// Set-Cookie: sessionId=12345; path=/; Secure; HttpOnly\r\n
// SourceMap: /path/to/source.map\r\n
// Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n
// TE: trailers, deflate\r\n
// Timing-Allow-Origin: *\r\n
// Trailer: Content-MD5\r\n
// Transfer-Encoding: chunked\r\n
// Upgrade: websocket\r\n
// Upgrade-Insecure-Requests: 1\r\n
// User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36\r\n
// Vary: Accept-Encoding, User-Agent\r\n
// Via: 1.1 example.com\r\n
// WWW-Authenticate: Basic realm="Secure Area"\r\n


TEST(Request, TEST9)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\nHost: example.com\r\nService-Worker-Navigation-Preload: true\r\nSet-Cookie: sessionId=12345; path=/; Secure; HttpOnly\r\nSourceMap: /path/to/source.map\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nTE: trailers, deflate\r\nTiming-Allow-Origin: *\r\nTrailer: Content-MD5\r\nTransfer-Encoding: chunked\r\nUpgrade: websocket\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36\r\nVary: Accept-Encoding, User-Agent\r\nVia: 1.1 example.com\r\nWWW-Authenticate: Basic realm=\"Secure Area\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "Service-Worker-Navigation-Preload", httprequest_test1) == true)
	{
		SingleFieldValue* val1 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Service-Worker-Navigation-Preload"));
		compair_valueset_report(val1->get_value(), "true");
	}
	// if (same_class_test(__LINE__, "Proxy-Authenticate", httprequest_test1) == true)
	// {
	// 	//map型
	// 	FieldValueMap* valmap2 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values("Proxy-Authenticate"));
	// 	std::map<std::string, std::string> valuemap2;
	// 	std::set<std::string> keys2;
	// 	valuemap2["sessionId"] = "12345";
	// 	valuemap2["path"] = "/";
	// 	valuemap2["path"] = "/";
	// 	keys2.insert("sessionId");
	// 	check(valmap2->get_value_map(), valuemap2, keys2);
	// }
	if (same_class_test(__LINE__, "SourceMap", httprequest_test1) == true)
	{
		SingleFieldValue* val3 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"SourceMap"));
		compair_valueset_report(val3->get_value(), "/path/to/source.map");
	}
	// if (same_class_test(__LINE__, "Strict-Transport-Security", httprequest_test1) == true)
	// {
	// 	FieldValueMap* valmap2 = static_cast<FieldValueMap*>(httprequest_test1.get_field_values("Strict-Transport-Security"));
	// 	std::map<std::string, std::string> valuemap2;
	// 	std::set<std::string> keys2;
	// 	valuemap2["max-age"] = "31536000";
	// 	valuemap2["path"] = "/";
	// 	valuemap2["path"] = "/";
	// 	keys2.insert("sessionId");
	// 	check(valmap2->get_value_map(), valuemap2, keys2);
	// }
	if (same_class_test(__LINE__, "TE", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"TE"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["trailers"] = 1.0;
		keyvalue4["deflate"] = 1.0;
		keys4.insert("trailers");
		keys4.insert("deflate");
		compair_valueweightarray_report(valweightarrayset4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "Timing-Allow-Origin", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Timing-Allow-Origin"));
		compair_valueset_report(val5->get_value(), "*");
	}
	if (same_class_test(__LINE__, "Trailer", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Trailer"));
		compair_valueset_report(val6->get_value(), "Content-MD5");
	}
	if (same_class_test(__LINE__, "Transfer-Encoding", httprequest_test1) == true)
	{
		MultiFieldValues* val7 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Transfer-Encoding"));
		std::set<std::string> vector7;
		vector7.insert("chunked");
		compare_vectors_report(val7->get_values(), vector7, 310);
	}
	if (same_class_test(__LINE__, "Upgrade", httprequest_test1) == true)
	{
		MultiFieldValues* val8 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Upgrade"));
		std::set<std::string> vector8;
		vector8.insert("websocket");
		compare_vectors_report(val8->get_values(), vector8, 310);
	}
	if (same_class_test(__LINE__, "Upgrade-Insecure-Requests", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Upgrade-Insecure-Requests"));
		compair_valueset_report(val9->get_value(), "1");
	}
	if (same_class_test(__LINE__, "User-Agent", httprequest_test1) == true)
	{
		SingleFieldValue* val10 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"User-Agent"));
		compair_valueset_report(val10->get_value(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36");
	}
	if (same_class_test(__LINE__, "Vary", httprequest_test1) == true)
	{
		MultiFieldValues* val11 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Vary"));
		std::set<std::string> vector11;
		vector11.insert("Accept-Encoding");
		vector11.insert("User-Agent");
		compare_vectors_report(val11->get_values(), vector11, 310);
	}
	if (same_class_test(__LINE__, "Vary", httprequest_test1) == true)
	{
		MultiFieldValues* val12 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"Vary"));
		std::set<std::string> vector12;
		vector12.insert("Accept-Encoding");
		vector12.insert("User-Agent");
		compare_vectors_report(val12->get_values(), vector12, 310);
	}
	if (same_class_test(__LINE__, "Via", httprequest_test1) == true)
	{
		SingleFieldValue* val13 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"Via"));
		compair_valueset_report(val13->get_value(), "1.1 example.com");
	}
	// if (same_class_test(__LINE__, "WWW-Authenticate", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values("WWW-Authenticate"));
	// 	std::set<std::string> vector1;
	// 	vector1.insert("Accept-Encoding");
	// 	vector1.insert("User-Agent");
	// 	check(val1->get_values(), vector1, 310);
	// }
}

//イレギュラーケース　数字系統の異常
