#include <climits>
#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

// "(),/:;<=>?@[\]{}
TEST(TestHttpMessageParser, IsDelimiter) {
	EXPECT_TRUE(HttpMessageParser::is_delimiters('"'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('('));
	EXPECT_TRUE(HttpMessageParser::is_delimiters(')'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters(','));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('/'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters(':'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters(';'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('<'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('='));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('>'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('?'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('@'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('['));
	EXPECT_TRUE(HttpMessageParser::is_delimiters(']'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('\\'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('{'));
	EXPECT_TRUE(HttpMessageParser::is_delimiters('}'));

	EXPECT_FALSE(HttpMessageParser::is_delimiters(' '));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('\t'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('\v'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('\r'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('\n'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('a'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('z'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('0'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('9'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('~'));
	EXPECT_FALSE(HttpMessageParser::is_delimiters('\0'));
}

TEST(TestHttpMessageParser, IsVchar) {
	EXPECT_TRUE(HttpMessageParser::is_vchar(0x21));
	EXPECT_TRUE(HttpMessageParser::is_vchar(0x7D));
	EXPECT_TRUE(HttpMessageParser::is_vchar(0x7E));

	EXPECT_FALSE(HttpMessageParser::is_vchar(0x00));
	EXPECT_FALSE(HttpMessageParser::is_vchar(0x20));
	EXPECT_FALSE(HttpMessageParser::is_vchar(0x7F));
	EXPECT_FALSE(HttpMessageParser::is_vchar(0xFF));
}

TEST(TestHttpMessageParser, IsObsText) {
	EXPECT_TRUE(HttpMessageParser::is_obs_text(0x80));
	EXPECT_TRUE(HttpMessageParser::is_obs_text(0xFF));

	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x00));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x10));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x20));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x30));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x40));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x50));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x50));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x60));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x70));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(0x79));
}

TEST(TestHttpMessageParser, IsFieldContent) {
	EXPECT_TRUE(HttpMessageParser::is_field_content("!"));
	EXPECT_TRUE(HttpMessageParser::is_field_content("! !"));
	EXPECT_TRUE(HttpMessageParser::is_field_content("abc123"));
	EXPECT_TRUE(HttpMessageParser::is_field_content("abc123 \taaa"));
	EXPECT_TRUE(HttpMessageParser::is_field_content("abc123 \t\""));
	EXPECT_TRUE(HttpMessageParser::is_field_content("' 123   abc';;;"));

	EXPECT_FALSE(HttpMessageParser::is_field_content(" "));
	EXPECT_FALSE(HttpMessageParser::is_field_content("aaa\t"));
}

TEST(TestHttpMessageParser, isTchar) {
	EXPECT_TRUE(HttpMessageParser::is_tchar('!'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('#'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('$'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('%'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('&'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('\''));
	EXPECT_TRUE(HttpMessageParser::is_tchar('*'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('+'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('-'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('.'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('^'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('_'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('`'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('|'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('~'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('0'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('9'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('a'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('z'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('A'));
	EXPECT_TRUE(HttpMessageParser::is_tchar('Z'));


	EXPECT_FALSE(HttpMessageParser::is_tchar('"'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('('));
	EXPECT_FALSE(HttpMessageParser::is_tchar(')'));
	EXPECT_FALSE(HttpMessageParser::is_tchar(','));
	EXPECT_FALSE(HttpMessageParser::is_tchar('/'));
	EXPECT_FALSE(HttpMessageParser::is_tchar(':'));
	EXPECT_FALSE(HttpMessageParser::is_tchar(';'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('<'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('='));
	EXPECT_FALSE(HttpMessageParser::is_tchar('>'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('?'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('@'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('['));
	EXPECT_FALSE(HttpMessageParser::is_tchar(']'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\\'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('{'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('}'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\0'));
	EXPECT_FALSE(HttpMessageParser::is_tchar(' '));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\t'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\n'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\r'));
	EXPECT_FALSE(HttpMessageParser::is_tchar('\v'));
}

TEST(TestHttpMessageParser, IsToken) {
	EXPECT_TRUE(HttpMessageParser::is_token("abc123"));
	EXPECT_TRUE(HttpMessageParser::is_token("hoge!^_hoge"));
	EXPECT_TRUE(HttpMessageParser::is_token("abc123_"));

	EXPECT_FALSE(HttpMessageParser::is_token(""));
	EXPECT_FALSE(HttpMessageParser::is_token("abc "));
	EXPECT_FALSE(HttpMessageParser::is_token("a;b"));
	EXPECT_FALSE(HttpMessageParser::is_token("123(c)"));
	EXPECT_FALSE(HttpMessageParser::is_token("a:b"));
}

TEST(TestHttpMessageParser, IsToken68) {
	EXPECT_TRUE(HttpMessageParser::is_token68("abc012-._~+/"));
	EXPECT_TRUE(HttpMessageParser::is_token68("a="));
	EXPECT_TRUE(HttpMessageParser::is_token68("abc="));
	EXPECT_TRUE(HttpMessageParser::is_token68("abc========================="));

	EXPECT_FALSE(HttpMessageParser::is_token68(""));
	EXPECT_FALSE(HttpMessageParser::is_token68("\"abc\""));
	EXPECT_FALSE(HttpMessageParser::is_token68("=abc"));
	EXPECT_FALSE(HttpMessageParser::is_token68("="));
	EXPECT_FALSE(HttpMessageParser::is_token68("a=b"));
	EXPECT_FALSE(HttpMessageParser::is_token68("===="));
	EXPECT_FALSE(HttpMessageParser::is_token68("====123==="));
}

TEST(TestHttpMessageParser, IsExtToken) {
	EXPECT_TRUE(HttpMessageParser::is_ext_token("abc123*"));
	EXPECT_TRUE(HttpMessageParser::is_ext_token("hoge!^_hoge*"));
	EXPECT_TRUE(HttpMessageParser::is_ext_token("abc123_*"));
	EXPECT_TRUE(HttpMessageParser::is_ext_token("**"));
	EXPECT_TRUE(HttpMessageParser::is_ext_token("***"));
	EXPECT_TRUE(HttpMessageParser::is_ext_token("***************"));

	EXPECT_FALSE(HttpMessageParser::is_ext_token(""));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("a"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("*"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("abc;*"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("123 ***"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("****1"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("****  a*"));
}

TEST(TestHttpMessageParser, IsQuotedPair) {
	EXPECT_TRUE(HttpMessageParser::is_quoted_pair("\\	", 0));
	EXPECT_TRUE(HttpMessageParser::is_quoted_pair("\\ ", 0));
	EXPECT_TRUE(HttpMessageParser::is_quoted_pair("\\!", 0));
	EXPECT_TRUE(HttpMessageParser::is_quoted_pair("012\\ ", 3));

	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("", 0));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("", 123));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("\\t", 1));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("\\t", 2));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("012\\ ", 0));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("012\\ ", 1));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("012\\ ", 2));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("012\\ ", 4));
}

TEST(TestHttpMessageParser, IsPctEncoded) {
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("%01", 0));
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("012%FF", 3));
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("%%ab", 1));

	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("%01", 10000));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("", 0));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("", 100));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("%0x", 0));
}

TEST(TestHttpMessageParser, IsQuotedString) {
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\"a\""));
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\"abc   \""));
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\"     \""));
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\" \""));
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\"\t\""));
	EXPECT_TRUE(HttpMessageParser::is_quoted_string("\"abc;\""));

	EXPECT_FALSE(HttpMessageParser::is_quoted_string(""));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("\"\""));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("'abc'"));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("\""));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("'"));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("\"'         "));
}

// todo: move
TEST(TestHttpMessageParser, SkipQuotedString) {
	std::size_t end;
	std::string str = "\"abc\"";
	HttpMessageParser::skip_quoted_string(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "012\"quoted string   \"21___";
	HttpMessageParser::skip_quoted_string(str, 3, &end);
	EXPECT_EQ(21, end);

	str = "012\"un quoted string   ";
	HttpMessageParser::skip_quoted_string(str, 3, &end);
	EXPECT_EQ(3, end);

	str = "\"";
	HttpMessageParser::skip_quoted_string(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	HttpMessageParser::skip_quoted_string(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	HttpMessageParser::skip_quoted_string(str, 10000, &end);
	EXPECT_EQ(0, end);
}

TEST(TestHttpMessageParser, IsWhiteSpace) {
	EXPECT_TRUE(HttpMessageParser::is_whitespace(' '));
	EXPECT_TRUE(HttpMessageParser::is_whitespace('	'));
	EXPECT_TRUE(HttpMessageParser::is_whitespace('\t'));

	EXPECT_FALSE(HttpMessageParser::is_whitespace('\0'));
	EXPECT_FALSE(HttpMessageParser::is_whitespace('\r'));
	EXPECT_FALSE(HttpMessageParser::is_whitespace('\v'));
}

TEST(TestHttpMessageParser, IsEndWithCR) {
	EXPECT_TRUE(HttpMessageParser::is_end_with_cr("abc\r"));
	EXPECT_TRUE(HttpMessageParser::is_end_with_cr("\r"));
	EXPECT_TRUE(HttpMessageParser::is_end_with_cr("abc\r\n\r\n   \r"));
	EXPECT_TRUE(HttpMessageParser::is_end_with_cr("\r\r\r\r\r\r"));

	EXPECT_FALSE(HttpMessageParser::is_end_with_cr(""));
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("\r\n"));
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("\v"));
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("\n"));
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("abc"));
}

TEST(TestHttpMessageParser, IsValidMethod) {
	EXPECT_TRUE(HttpMessageParser::is_valid_method("GET"));
	EXPECT_TRUE(HttpMessageParser::is_valid_method("POST"));
	EXPECT_TRUE(HttpMessageParser::is_valid_method("DELETE"));

	EXPECT_FALSE(HttpMessageParser::is_valid_method(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_method("get"));
	EXPECT_FALSE(HttpMessageParser::is_valid_method("HEADER"));
	EXPECT_FALSE(HttpMessageParser::is_valid_method("GET "));
	EXPECT_FALSE(HttpMessageParser::is_valid_method("GETGET"));
}

TEST(TestHttpMessageParser, IsValidRequestTarget) {
	EXPECT_TRUE(HttpMessageParser::is_valid_request_target("/"));
	EXPECT_TRUE(HttpMessageParser::is_valid_request_target("/index.html"));

	EXPECT_FALSE(HttpMessageParser::is_valid_request_target(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\t"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\n"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\r\n"));
}

TEST(TestHttpMessageParser, IsValidHttpVersion) {
	EXPECT_TRUE(HttpMessageParser::is_valid_http_version("HTTP/1.1"));
	EXPECT_TRUE(HttpMessageParser::is_valid_http_version("HTTP/2.0"));
	EXPECT_TRUE(HttpMessageParser::is_valid_http_version("HTTP/3.0"));

	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("http/1.1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("HTTP/1.1 "));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("HTTP1.1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("HTTP/1.11\r"));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("HTTP/1.1\r"));
}

TEST(TestHttpMessageParser, IsHeaderBodySeparetor) {
	EXPECT_TRUE(HttpMessageParser::is_header_body_separator("\r"));

	EXPECT_FALSE(HttpMessageParser::is_header_body_separator(""));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator(" \r\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\r\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\r\n\r"));
}

// TEST(TestHttpMessageParser, ) {
// 	EXPECT_TRUE(HttpMessageParser::);
//
// 	EXPECT_FALSE(HttpMessageParser::);
// }

// TEST(TestHttpMessageParser, ) {
// 	EXPECT_TRUE(HttpMessageParser::);
//
// 	EXPECT_FALSE(HttpMessageParser::);
// }

// TEST(TestHttpMessageParser, ) {
// 	EXPECT_TRUE(HttpMessageParser::);
//
// 	EXPECT_FALSE(HttpMessageParser::);
// }

// TEST(TestHttpMessageParser, ) {
// 	EXPECT_TRUE(HttpMessageParser::);
//
// 	EXPECT_FALSE(HttpMessageParser::);
// }

// TEST(TestHttpMessageParser, ) {
// 	EXPECT_TRUE(HttpMessageParser::);
//
// 	EXPECT_FALSE(HttpMessageParser::);
// }

