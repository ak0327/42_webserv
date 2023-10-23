#include <string>
#include <algorithm>
#include "gtest/gtest.h"
#include "Constant.hpp"
#include "Color.hpp"
#include "Date.hpp"
#include "Debug.hpp"
#include "Error.hpp"
#include "HttpRequest.hpp"
#include "MultiFieldValues.hpp"
#include "RequestLine.hpp"
#include "Result.hpp"
#include "SingleFieldValue.hpp"
#include "StringHandler.hpp"
#include "TwoValueSet.hpp"
#include "MapFieldValues.hpp"
#include "MapSetFieldValues.hpp"
#include "ValueWeightArraySet.hpp"

typedef std::set<std::map<std::string, std::string> > map_set;

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

void compare_inputvalue_truevalue_linkclass(std::map<std::string,
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

void compare_vectors_report(std::set<std::string> target_vector,
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

void compare_map_report(std::map<std::string, std::set<std::string> > target_map,
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

void compare_daymap_report(Date *targetdatevalue,
						   std::string day_name,
						   std::string day,
						   std::string month,
						   std::string year,
						   std::string hour,
						   std::string minute,
						   std::string second)
{
	EXPECT_EQ(targetdatevalue->get_day_name(), day_name);
	EXPECT_EQ(targetdatevalue->get_day(), day);
	EXPECT_EQ(targetdatevalue->get_month(), month);
	EXPECT_EQ(targetdatevalue->get_year(), year);
	EXPECT_EQ(targetdatevalue->get_hour(), hour);
	EXPECT_EQ(targetdatevalue->get_minute(), minute);
	EXPECT_EQ(targetdatevalue->get_second(), second);
}

void compair_valuemapset_withfirstvalue_report(std::string only_value,
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

void check(std::map<std::string, std::string> target_wordmap,
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

void compair_valueweightarray_report(std::map<std::string, double> target_wordmap,
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

void compair_twovaluemap_report(const std::string &first_target_word,
								const std::string &second_target_word,
								const std::string &exp_1,
								const std::string &exp_2)
{
	EXPECT_EQ(first_target_word, exp_1);
	EXPECT_EQ(second_target_word, exp_2);
}

void compair_valueset_report(const std::string &target_word, const std::string &expected_word)
{
	EXPECT_EQ(target_word, expected_word);
}

bool same_class_test(int line, const char *key, HttpRequest &target)
{
	std::map<std::string, FieldValueBase*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValueBase*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == std::string(key))
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

bool keyword_doesnot_exist(int line, const char *key, HttpRequest &target)
{
	std::map<std::string, FieldValueBase*>keyvaluemap = target.get_request_header_fields();
	std::map<std::string, FieldValueBase*>::iterator itr_now = keyvaluemap.begin();
	while (itr_now != keyvaluemap.end())
	{
		if (itr_now->first == std::string(key))
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
	if (same_class_test(__LINE__, "host", httprequest_test1) == true)
	{
		FieldValueBase *field_values = httprequest_test1.get_field_values(std::string(HOST));
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();

		std::map<std::string, std::string>::const_iterator itr;
		itr = actual_map.find(std::string(URI_HOST));
		EXPECT_EQ("www.example.com", itr->second);
	}
	if (same_class_test(__LINE__, "user-agent", httprequest_test1) == true)
	{
		SingleFieldValue* val = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"user-agent"));
		compair_valueset_report( val->get_value(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept"));
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
	if (same_class_test(__LINE__, "accept-encoding", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray5 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept-encoding"));
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
									  "Upgrade-Insecure-Requests: 1\r\n"
									  "\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	if (same_class_test(__LINE__, "host", httprequest_test1) == true)
	{
		FieldValueBase *field_values = httprequest_test1.get_field_values(std::string(HOST));
		MapFieldValues *multi_field_values = dynamic_cast<MapFieldValues *>(field_values);
		std::map<std::string, std::string> actual_map = multi_field_values->get_value_map();

		std::map<std::string, std::string>::const_iterator itr;
		itr = actual_map.find(std::string(URI_HOST));
		EXPECT_EQ("example.com", itr->second);
	}
	if (same_class_test(__LINE__, "user-agent", httprequest_test1) == true)
	{
		SingleFieldValue* val2 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"user-agent"));
		compair_valueset_report( val2->get_value(), "YourUserAgent");
	}
	if (same_class_test(__LINE__, "accept", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray3 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept"));
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
	if (same_class_test(__LINE__, "accept-language", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept-language"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["en-US"] = 1.0;
		keyvalue4["en"] = 0.5;
		keys4.insert("en-US");
		keys4.insert("en");
		compair_valueweightarray_report(valweightarray4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "accept-encoding", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray5 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept-encoding"));
		std::map<std::string, double> keyvalue5;
		std::set<std::string> keys5;
		keyvalue5["gzip"] = 1.0;
		keyvalue5["deflate"] = 1.0;
		keys5.insert("gzip");
		keys5.insert("deflate");
		compair_valueweightarray_report(valweightarray5->get_valueweight_set(), keyvalue5, keys5);
	}
	if (same_class_test(__LINE__, "connection", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"connection"));
		compair_valueset_report( val6->get_value(), "keep-alive");
	}
	if (same_class_test(__LINE__, "referer", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"referer"));
		compair_valueset_report( val7->get_value(), "http://www.example.com/referrer");
	}

	// todo:later
	// if (same_class_test(__LINE__, "cookie", httprequest_test1) == true)
	// {
	// 	//map型
	// 	MapFieldValues* valmap8 = static_cast<MapFieldValues*>(httprequest_test1.get_field_values(
	// 			"cookie"));
	// 	std::map<std::string, std::string> valuemap8;
	// 	std::set<std::string> keys8;
	// 	valuemap8["session_id"] = "12345";
	// 	valuemap8["user"] = "JohnDoe";
	// 	keys8.insert("session_id");
	// 	keys8.insert("user");
	// 	check( valmap8->get_value_map(), valuemap8, keys8);
	// }

	//Authorization
	if (same_class_test(__LINE__, "authorization", httprequest_test1) == true)
	{
		//map型 Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
		MapFieldValues* twoval9 = dynamic_cast<MapFieldValues*>(httprequest_test1.get_field_values(
				"authorization"));
		compair_twovaluemap_report(twoval9->get_value_map()[std::string(AUTH_SCHEME)],
								   twoval9->get_value_map()[std::string(AUTH_PARAM)],
								   "Basic",
								   "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
	}
	if (same_class_test(__LINE__, "upgrade-insecure-requests", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"upgrade-insecure-requests"));
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
	if (same_class_test(__LINE__, "accept-language", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarray4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"accept-language"));
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

TEST(Request, TEST3)
{
	const std::string TEST_REQUEST2 = "GET /path/to/resource HTTP/1.1\r\n"
									  "host: example\r\n"
									  "X-Forwarded-For: 192.168.1.1\r\n"
									  "X-Request-ID: 12345\r\n"
									  "X-Requested-With: XMLHttpRequest\r\n"
									  "If-None-Match: some_etag\r\n"
									  "If-Modified-Since: Fri, 01 Sep 2023 12:00:00 GMT\r\n"
									  "Max-Forwards: 10\r\n"
									  "TE: trailers, deflate;q=0.5\r\n"
									  "From: sender@example.com\r\n"
									  "Origin: http://www.origin-example.com\r\n"
									  "Via: 1.0 proxy.example.com (Apache/1.1)\r\n"
									  "Age: 3600\r\n"
									  "Warning: 199 Miscellaneous warning\r\n"
									  "Access-Control-Allow-Origin: *\r\n"
									  "X-Frame-Options: SAMEORIGIN\r\n"
									  "\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	EXPECT_EQ(STATUS_OK, httprequest_test1.get_status_code());

	// todo: later
	// if (same_class_test(__LINE__, "if-none-match", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"if-none-match"));
	// 	std::set<std::string> vector1;
	// 	vector1.insert("some_etag");
	// 	compare_vectors_report(val1->get_values(), vector1, __LINE__);
	// }

	if (same_class_test(__LINE__, "if-modified-since", httprequest_test1) == true)
	{
		Date *dateval2 = dynamic_cast<Date*>(httprequest_test1.get_field_values(
				"if-modified-since"));
		compare_daymap_report(dateval2, "Fri", "01", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "max-forwards", httprequest_test1) == true)
	{
		SingleFieldValue* val3 = dynamic_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"max-forwards"));
		compair_valueset_report(val3->get_value(), "10");
	}

	// todo: later
	// if (same_class_test(__LINE__, "te", httprequest_test1) == true)
	// {
	// 	ValueWeightArraySet* valweightarrayset4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
	// 			"te"));
	// 	std::map<std::string, double> keyvalue4;
	// 	std::set<std::string> keys4;
	// 	keyvalue4["trailers"] = 1.0;
	// 	keyvalue4["deflate"] = 0.5;
	// 	keys4.insert("trailers");
	// 	keys4.insert("deflate");
	// 	compair_valueweightarray_report(valweightarrayset4->get_valueweight_set(), keyvalue4, keys4);
	// }

	// todo: later
	// if (same_class_test(__LINE__, "from", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"from"));
	// 	compair_valueset_report(val5->get_value(), "sender@example.com");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "origin", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"origin"));
	// 	compair_valueset_report(val6->get_value(), "http://www.origin-example.com");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "via", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"via"));
	// 	compair_valueset_report(val7->get_value(), "1.0 proxy.example.com (Apache/1.1)");
	// }
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
									  "X-Frame-Options: SAMEORIGIN\r\n"
									  "\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/path/to/resource");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	// todo: later
	// if (same_class_test(__LINE__, "if-none-match", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val1 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"if-none-match"));
	// 	std::set<std::string> vector1;
	// 	vector1.insert("some  _etag");
	// 	compare_vectors_report(val1->get_values(), vector1, __LINE__);
	// }
	// keyword_doesnot_exist(__LINE__, "if-modified-since", httprequest_test1);
	// keyword_doesnot_exist(__LINE__, "max-forwards", httprequest_test1);
	// keyword_doesnot_exist(__LINE__, "te", httprequest_test1);

	// todo: later
	// if (same_class_test(__LINE__, "from", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"from"));
	// 	compair_valueset_report(val5->get_value(), "sender@ example.com");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "origin", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"origin"));
	// 	compair_valueset_report(val6->get_value(), "http:// www.origin-example.com");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "Via", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"Via"));
	// 	compair_valueset_report(val7->get_value(), "1.0 proxy.example.com (Apache/1.1)");
	// }
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
	keyword_doesnot_exist(__LINE__, "max-forwards", httprequest_test1);
}

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
	// todo later
	// if (same_class_test(__LINE__, "accept-charset", httprequest_test1) == true)
	// {
	// 	ValueWeightArraySet* valweightarrayset2 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
	// 			"accept-charset"));
	// 	std::map<std::string, double> keyvalue2;
	// 	std::set<std::string> keys2;
	// 	keyvalue2["utf-8"] = 1.0;
	// 	keys2.insert("utf-8");
	// 	compair_valueweightarray_report(valweightarrayset2->get_valueweight_set(), keyvalue2, keys2);
	// }
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
	// todo: later
	// if (same_class_test(__LINE__, "accept-charset", httprequest_test1) == true)
	// {
	// 	ValueWeightArraySet* valweightarrayset2 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
	// 			"accept-charset"));
	// 	std::map<std::string, double> keyvalue2;
	// 	std::set<std::string> keys2;
	// 	keyvalue2["utf-8"] = 1.0;
	// 	keys2.insert("utf-8");
	// 	compair_valueweightarray_report(valweightarrayset2->get_valueweight_set(), keyvalue2, keys2);
	// }
}

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

	// todo: later
	// if (same_class_test(__LINE__, "access-control-request-headers", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val3 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"access-control-request-headers"));
	// 	std::set<std::string> vector3;
	// 	vector3.insert("authorization");
	// 	vector3.insert("content-type");
	// 	compare_vectors_report(val3->get_values(), vector3, 478);
	// }

	// todo: later
	// if (same_class_test(__LINE__, "access-control-request-method", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"access-control-request-method"));
	// 	compair_valueset_report(val4->get_value(), "POST");
	// }
}

TEST(Request, TEST6)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Content-Disposition: attachment; filename=\"example.txt\"\r\n"
									  "Content-Encoding: gzip\r\n"
									  // "Content-Language: en-US\r\n" // todo:later
									  "Content-Length: 1024\r\n"
									  "Content-Location: /documents/example.txt\r\n"
									  "Content-Range: bytes 0-511/1024\r\n"
									  "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'\r\n"
									  "Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self' 'unsafe-inline'; report-uri /csp-report\r\n"
									  "Content-Type: application/json\r\n"
									  "\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	// todo: later
	// if (same_class_test(__LINE__, "content-disposition", httprequest_test1) == true)
	// {
	// 	//map型
	// 	MapFieldValues* valmap1 = static_cast<MapFieldValues*>(httprequest_test1.get_field_values(
	// 			"content-disposition"));
	// 	std::map<std::string, std::string> valuemap1;
	// 	std::set<std::string> keys1;
	// 	valuemap1["filename"] = "\"example.txt\"";
	// 	keys1.insert("filename");
	// 	compair_valuemapset_withfirstvalue_report( valmap1->get_only_value(), valmap1->get_value_map(), "attachment", valuemap1, keys1);
	// }

	// todo: later
	// if (same_class_test(__LINE__, "content-encoding", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val2 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"content-encoding"));
	// 	std::set<std::string> vector2;
	// 	vector2.insert("gzip");
	// 	compare_vectors_report(val2->get_values(), vector2, 571);
	// }

	// todo: later
	// if (same_class_test(__LINE__, "content-language", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val3 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"content-language"));
	// 	std::set<std::string> vector3;
	// 	vector3.insert("en-US");
	// 	compare_vectors_report(val3->get_values(), vector3, 578);
	// }

	// todo: later
	// if (same_class_test(__LINE__, "content-length", httprequest_test1) == true)
	// {
	//
	// 	SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"content-length"));
	// 	compair_valueset_report(val4->get_value(), "1024");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "content-location", httprequest_test1) == true)
	// {
	// 	SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
	// 			"content-location"));
	// 	compair_valueset_report(val5->get_value(), "/documents/example.txt");
	// }

	// todo: later
	// if (same_class_test(__LINE__, "content-type", httprequest_test1) == true)
	// {
	// 	//map型
	// 	MapFieldValues* valmap8 = static_cast<MapFieldValues*>(httprequest_test1.get_field_values(
	// 			"content-type"));
	// 	EXPECT_EQ(valmap8->get_only_value(), "application/json");
	// }
}

TEST(Request, TEST_CONTENT_LENGTH)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Content-Length: -1\r\n"
									  "Content-Length: 10000000000000000\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");
	keyword_doesnot_exist(__LINE__, "content-length", httprequest_test1);
}

TEST(Request, TEST7)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Cross-Origin-Embedder-Policy: require-corp\r\n"
									  "Cross-Origin-Opener-Policy: same-origin-allow-popups\r\n"
									  "Cross-Origin-Resource-Policy: same-origin\r\n"
									  "Date: Fri, 15 Sep 2023 12:00:00 GMT\r\n"
									  "Expect: 100-continue\r\n"
									  "Expires: Fri, 15 Sep 2023 13:00:00 GMT\r\n"
									  "Forwarded: for=192.0.2.60;proto=http;by=203.0.113.43\r\n"
									  "Host: example.com\r\n"
									  "If-Match: \"etag123\"\r\n"
									  "If-Range: \"etag123\"\r\n"
									  "If-Unmodified-Since: Fri, 15 Sep 2023 11:30:00 GMT\r\n"
									  "Keep-Alive: timeout=5, max=1000\r\n"
									  "Last-Modified: Fri, 15 Sep 2023 11:45:00 GMT\r\n"
									  "Link: <https://example.com/style.css>; rel=preload; as=style\r\n"
									  "Location: https://example.com/redirected-page\r\n"
									  "\r\n";

	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "date", httprequest_test1) == true)
	{
		// Fri, 15 Sep 2023 12:00:00 GMT
		Date *dateval4 = static_cast<Date*>(httprequest_test1.get_field_values(
				"date"));
		compare_daymap_report(dateval4, "Fri", "15", "Sep", "2023", "12", "00", "00");
	}
	if (same_class_test(__LINE__, "expect", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"expect"));
		compair_valueset_report(val5->get_value(), "100-continue");
	}
	if (same_class_test(__LINE__, "forwarded", httprequest_test1) == true)
	{
		MapFieldValues* valmap7 = static_cast<MapFieldValues*>(httprequest_test1.get_field_values(
				"forwarded"));
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
	if (same_class_test(__LINE__, "if-match", httprequest_test1) == true)
	{
		MultiFieldValues* val8 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"if-match"));
		std::set<std::string> vector8;
		vector8.insert("\"etag123\"");
		compare_vectors_report(val8->get_values(), vector8, 685);
	}
	if (same_class_test(__LINE__, "if-range", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"if-range"));
		compair_valueset_report(val9->get_value(), "\"etag123\"");
	}
	if (same_class_test(__LINE__, "if-unmodified-since", httprequest_test1) == true)
	{
		// Thu, 15 Sep 2023 11:30:00 GMT
		Date *dateval10 = static_cast<Date*>(httprequest_test1.get_field_values(
				"if-unmodified-since"));
		compare_daymap_report(dateval10, "Fri", "15", "Sep", "2023", "11", "30", "00");
	}
	if (same_class_test(__LINE__, "keep-alive", httprequest_test1) == true)
	{
		MapFieldValues* valmap11 = static_cast<MapFieldValues*>(httprequest_test1.get_field_values(
				"keep-alive"));
		std::map<std::string, std::string> valuemap11;
		std::set<std::string> keys11;
		valuemap11["timeout"] = "5";
		valuemap11["max"] = "1000";
		keys11.insert("timeout");
		keys11.insert("max");
		check(valmap11->get_value_map(), valuemap11, keys11);
	}
	if (same_class_test(__LINE__, "last-modified", httprequest_test1) == true)
	{
		Date *dateval12 = static_cast<Date*>(httprequest_test1.get_field_values(
				"last-modified"));
		compare_daymap_report(dateval12, "Fri", "15", "Sep", "2023", "11", "45", "00");
	}
	if (same_class_test(__LINE__, "link", httprequest_test1) == true)
	{
		std::string field_name = std::string(LINK);
		bool has_field_name = httprequest_test1.is_valid_field_name_registered(field_name);

		EXPECT_TRUE(has_field_name);

		if (has_field_name) {
			FieldValueBase *field_values = httprequest_test1.get_field_values(field_name);
			MapSetFieldValues *map_set_field_values = dynamic_cast<MapSetFieldValues *>(field_values);

			map_set actual_map_set = map_set_field_values->get_map_set_values();
			map_set expected_map_set = {
					{{std::string(URI_REFERENCE), "https://example.com/style.css"},
					 {"rel", "preload"},
					 {"as", "style"},
					}};

			EXPECT_EQ(actual_map_set.size(), expected_map_set.size());

			map_set::const_iterator actual_map_set_itr = actual_map_set.begin();
			map_set::const_iterator expected_map_set_itr = expected_map_set.begin();

			while (actual_map_set_itr != actual_map_set.end() && expected_map_set_itr != expected_map_set.end()) {
				std::map<std::string, std::string> actual_map = *actual_map_set_itr;
				std::map<std::string, std::string> expected_map = *expected_map_set_itr;;

				EXPECT_EQ(actual_map.size(), expected_map.size());
				std::map<std::string, std::string>::const_iterator actual_map_itr = actual_map.begin();
				std::map<std::string, std::string>::const_iterator expected_map_itr = expected_map.begin();

				while (actual_map_itr != actual_map.end() && expected_map_itr != expected_map.end()) {
					EXPECT_EQ(actual_map_itr->second, expected_map_itr->second);

					++actual_map_itr;
					++expected_map_itr;
				}
				EXPECT_TRUE(actual_map_itr == actual_map.end());
				EXPECT_TRUE(expected_map_itr == expected_map.end());

				++actual_map_set_itr;
				++expected_map_set_itr;
			}
			EXPECT_TRUE(actual_map_set_itr == actual_map_set.end());
			EXPECT_TRUE(expected_map_set_itr == expected_map_set.end());

		} else {
			ADD_FAILURE() << field_name << " not found";
		}

		EXPECT_EQ(STATUS_OK, httprequest_test1.get_status_code());

	}
}

TEST(Request, TEST8)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Permission-Policy: geolocation=(self \"https://example.com\"), camera=()\r\n"
									  "Proxy-Authenticate: Basic realm=\"Proxy Server\"\r\n"
									  "Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n"
									  "Referer: https://example.com/previous-page\r\n"
									  "Retry-After: 120\r\n"
									  "Sec-Fetch-Dest: document\r\n"
									  "Sec-Fetch-Mode: navigate\r\n"
									  "Sec-Fetch-Site: same-origin\r\n"
									  "Sec-Fetch-User: ?1\r\n"
									  "Sec-Purpose: prefetch\r\n"
									  "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
									  "Server: Apache/2.4.41 (Ubuntu)\r\n"
									  "\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "sec-fetch-dest", httprequest_test1) == true)
	{
		SingleFieldValue* val4 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-fetch-dest"));
		compair_valueset_report(val4->get_value(), "document");
	}
	if (same_class_test(__LINE__, "sec-fetch-mode", httprequest_test1) == true)
	{
		SingleFieldValue* val5 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-fetch-mode"));
		compair_valueset_report(val5->get_value(), "navigate");
	}
	if (same_class_test(__LINE__, "sec-fetch-site", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-fetch-site"));
		compair_valueset_report(val6->get_value(), "same-origin");
	}
	if (same_class_test(__LINE__, "sec-fetch-site", httprequest_test1) == true)
	{
		SingleFieldValue* val7 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-fetch-site"));
		compair_valueset_report(val7->get_value(), "same-origin");
	}
	if (same_class_test(__LINE__, "sec-fetch-user", httprequest_test1) == true)
	{
		SingleFieldValue* val8 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-fetch-user"));
		compair_valueset_report(val8->get_value(), "?1");
	}
	if (same_class_test(__LINE__, "sec-purpose", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"sec-purpose"));
		compair_valueset_report(val9->get_value(), "prefetch");
	}
}

TEST(Request, TEST9)
{
	const std::string TEST_REQUEST2 = "GET /example HTTP/1.1\r\n"
									  "Host: example.com\r\n"
									  "Service-Worker-Navigation-Preload: true\r\n"
									  "Set-Cookie: sessionId=12345; path=/; Secure; HttpOnly\r\n"
									  "SourceMap: /path/to/source.map\r\n"
									  "Strict-Transport-Security: max-age=31536000; includeSubDomains\r\n"
									  "TE: trailers, deflate\r\n"
									  "Timing-Allow-Origin: *\r\n"
									  "Trailer: Content-MD5\r\n"
									  "Transfer-Encoding: chunked\r\n"
									  "Upgrade: websocket\r\n"
									  "Upgrade-Insecure-Requests: 1\r\n"
									  "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36\r\nVary: Accept-Encoding, User-Agent\r\nVia: 1.1 example.com\r\nWWW-Authenticate: Basic realm=\"Secure Area\"\r\n";
	HttpRequest httprequest_test1(TEST_REQUEST2);
	EXPECT_EQ(httprequest_test1.get_method(), "GET");
	EXPECT_EQ(httprequest_test1.get_request_target(), "/example");
	EXPECT_EQ(httprequest_test1.get_http_version(), "HTTP/1.1");

	if (same_class_test(__LINE__, "service-worker-navigation-preload", httprequest_test1) == true)
	{
		SingleFieldValue* val1 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"service-worker-navigation-preload"));
		compair_valueset_report(val1->get_value(), "true");
	}
	if (same_class_test(__LINE__, "te", httprequest_test1) == true)
	{
		ValueWeightArraySet* valweightarrayset4 = static_cast<ValueWeightArraySet*>(httprequest_test1.get_field_values(
				"te"));
		std::map<std::string, double> keyvalue4;
		std::set<std::string> keys4;
		keyvalue4["trailers"] = 1.0;
		keyvalue4["deflate"] = 1.0;
		keys4.insert("trailers");
		keys4.insert("deflate");
		compair_valueweightarray_report(valweightarrayset4->get_valueweight_set(), keyvalue4, keys4);
	}
	if (same_class_test(__LINE__, "trailer", httprequest_test1) == true)
	{
		SingleFieldValue* val6 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"trailer"));
		compair_valueset_report(val6->get_value(), "content-md5");
	}
	if (same_class_test(__LINE__, "transfer-encoding", httprequest_test1) == true)
	{
		MultiFieldValues* val7 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
				"transfer-encoding"));
		std::set<std::string> vector7;
		vector7.insert("chunked");
		compare_vectors_report(val7->get_values(), vector7, 310);
	}
	// todo: later
	// if (same_class_test(__LINE__, "upgrade", httprequest_test1) == true)
	// {
	// 	MultiFieldValues* val8 = static_cast<MultiFieldValues*>(httprequest_test1.get_field_values(
	// 			"upgrade"));
	// 	std::set<std::string> vector8;
	// 	vector8.insert("websocket");
	// 	compare_vectors_report(val8->get_values(), vector8, 310);
	// }
	if (same_class_test(__LINE__, "upgrade-insecure-requests", httprequest_test1) == true)
	{
		SingleFieldValue* val9 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"upgrade-insecure-requests"));
		compair_valueset_report(val9->get_value(), "1");
	}
	if (same_class_test(__LINE__, "user-agent", httprequest_test1) == true)
	{
		SingleFieldValue* val10 = static_cast<SingleFieldValue*>(httprequest_test1.get_field_values(
				"user-agent"));
		compair_valueset_report(val10->get_value(), "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.150 Safari/537.36");
	}
}

//イレギュラーケース　数字系統の異常
