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
	EXPECT_TRUE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x21)));
	EXPECT_TRUE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x7D)));
	EXPECT_TRUE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x7E)));

	EXPECT_FALSE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x00)));
	EXPECT_FALSE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x20)));
	EXPECT_FALSE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0x7F)));
	EXPECT_FALSE(HttpMessageParser::is_vchar(static_cast<unsigned char>(0xFF)));
}

TEST(TestHttpMessageParser, IsObsText) {
	EXPECT_TRUE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x80)));
	EXPECT_TRUE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0xFF)));

	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x00)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x10)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x20)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x30)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x40)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x50)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x50)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x60)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x70)));
	EXPECT_FALSE(HttpMessageParser::is_obs_text(static_cast<unsigned char>(0x79)));
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
	EXPECT_FALSE(HttpMessageParser::is_field_content(""));
	EXPECT_FALSE(HttpMessageParser::is_field_content("\0"));
	EXPECT_FALSE(HttpMessageParser::is_field_content("\0\0a"));
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

TEST(TestHttpMessageParser, IsCtext) {
	EXPECT_TRUE(HttpMessageParser::is_ctext('\t'));
	EXPECT_TRUE(HttpMessageParser::is_ctext(' '));
	EXPECT_TRUE(HttpMessageParser::is_ctext('!'));
	EXPECT_TRUE(HttpMessageParser::is_ctext('\''));
	EXPECT_TRUE(HttpMessageParser::is_ctext('*'));
	EXPECT_TRUE(HttpMessageParser::is_ctext('a'));
	EXPECT_TRUE(HttpMessageParser::is_ctext('['));
	EXPECT_TRUE(HttpMessageParser::is_ctext(']'));
	EXPECT_TRUE(HttpMessageParser::is_ctext('~'));

	EXPECT_FALSE(HttpMessageParser::is_ctext('\0'));
	EXPECT_FALSE(HttpMessageParser::is_ctext('\n'));
	EXPECT_FALSE(HttpMessageParser::is_ctext('('));
	EXPECT_FALSE(HttpMessageParser::is_ctext(')'));
	EXPECT_FALSE(HttpMessageParser::is_ctext('\\'));
}

TEST(TestHttpMessageParser, IsSingleton) {
	EXPECT_TRUE(HttpMessageParser::is_singleton('0'));
	EXPECT_TRUE(HttpMessageParser::is_singleton('9'));
	EXPECT_TRUE(HttpMessageParser::is_singleton('a'));
	EXPECT_TRUE(HttpMessageParser::is_singleton('z'));
	EXPECT_TRUE(HttpMessageParser::is_singleton('A'));
	EXPECT_TRUE(HttpMessageParser::is_singleton('Z'));

	EXPECT_FALSE(HttpMessageParser::is_singleton('x'));
	EXPECT_FALSE(HttpMessageParser::is_singleton('X'));
	EXPECT_FALSE(HttpMessageParser::is_singleton('*'));
	EXPECT_FALSE(HttpMessageParser::is_singleton('\0'));
	EXPECT_FALSE(HttpMessageParser::is_singleton(' '));
	EXPECT_FALSE(HttpMessageParser::is_singleton('\t'));
	EXPECT_FALSE(HttpMessageParser::is_singleton('\n'));
	EXPECT_FALSE(HttpMessageParser::is_singleton('\r'));
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
	EXPECT_FALSE(HttpMessageParser::is_token("\0"));
	EXPECT_FALSE(HttpMessageParser::is_token("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_token68("\0"));
	EXPECT_FALSE(HttpMessageParser::is_token68("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_ext_token("\0"));
	EXPECT_FALSE(HttpMessageParser::is_ext_token("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("\0", 0));
	EXPECT_FALSE(HttpMessageParser::is_quoted_pair("\0aa", 0));
}

TEST(TestHttpMessageParser, IsPctEncoded) {
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("%01", 0));
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("012%FF", 3));
	EXPECT_TRUE(HttpMessageParser::is_pct_encoded("%%ab", 1));

	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("%01", 10000));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("", 0));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("", 100));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("%0x", 0));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("\0", 0));
	EXPECT_FALSE(HttpMessageParser::is_pct_encoded("\0aa", 0));
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
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("\0"));
	EXPECT_FALSE(HttpMessageParser::is_quoted_string("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("\0"));
	EXPECT_FALSE(HttpMessageParser::is_end_with_cr("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_valid_method("\0"));
	EXPECT_FALSE(HttpMessageParser::is_valid_method("\0aa"));
}

TEST(TestHttpMessageParser, IsValidRequestTarget) {
	EXPECT_TRUE(HttpMessageParser::is_valid_request_target("/"));
	EXPECT_TRUE(HttpMessageParser::is_valid_request_target("/index.html"));

	EXPECT_FALSE(HttpMessageParser::is_valid_request_target(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\t"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\n"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\r\n"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\0"));
	EXPECT_FALSE(HttpMessageParser::is_valid_request_target("\0aa"));
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
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("\0"));
	EXPECT_FALSE(HttpMessageParser::is_valid_http_version("\0aa"));
}

TEST(TestHttpMessageParser, IsHeaderBodySeparetor) {
	EXPECT_TRUE(HttpMessageParser::is_header_body_separator("\r"));

	EXPECT_FALSE(HttpMessageParser::is_header_body_separator(""));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator(" \r\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\r\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\n"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\r\n\r"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\0"));
	EXPECT_FALSE(HttpMessageParser::is_header_body_separator("\0aa"));
}

TEST(TestHttpMessageParser, TestIsIRREGULAR) {
	EXPECT_TRUE(HttpMessageParser::is_irregular("en-GB-oed"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-ami"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-bnn"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-default"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-enochian"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-hak"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-klingon"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-lux"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-mingo"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-navajo"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-pwn"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-tao"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-tay"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("i-tsu"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("sgn-BE-FR"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("sgn-BE-NL"));
	EXPECT_TRUE(HttpMessageParser::is_irregular("sgn-CH-DE"));

	EXPECT_FALSE(HttpMessageParser::is_irregular(""));
	EXPECT_FALSE(HttpMessageParser::is_irregular("aaa"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("art-lojban"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("cel-gaulish"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("no-bok"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("no-nyn"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-guoyu"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-hakka"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-min"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-min-nan"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-xiang"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("\0"));
	EXPECT_FALSE(HttpMessageParser::is_irregular("\0aa"));
}

TEST(TestHttpMessageParser, IsRegular) {
	EXPECT_TRUE(HttpMessageParser::is_regular("art-lojban"));
	EXPECT_TRUE(HttpMessageParser::is_regular("cel-gaulish"));
	EXPECT_TRUE(HttpMessageParser::is_regular("no-bok"));
	EXPECT_TRUE(HttpMessageParser::is_regular("no-nyn"));
	EXPECT_TRUE(HttpMessageParser::is_regular("zh-guoyu"));
	EXPECT_TRUE(HttpMessageParser::is_regular("zh-hakka"));
	EXPECT_TRUE(HttpMessageParser::is_regular("zh-min"));
	EXPECT_TRUE(HttpMessageParser::is_regular("zh-min-nan"));
	EXPECT_TRUE(HttpMessageParser::is_regular("zh-xiang"));

	EXPECT_FALSE(HttpMessageParser::is_regular(""));
	EXPECT_FALSE(HttpMessageParser::is_regular("aaa"));
	EXPECT_FALSE(HttpMessageParser::is_regular("en-GB-oed"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-ami"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-bnn"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-default"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-enochian"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-hak"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-klingon"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-lux"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-mingo"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-navajo"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-pwn"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-tao"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-tay"));
	EXPECT_FALSE(HttpMessageParser::is_regular("i-tsu"));
	EXPECT_FALSE(HttpMessageParser::is_regular("sgn-BE-FR"));
	EXPECT_FALSE(HttpMessageParser::is_regular("sgn-BE-NL"));
	EXPECT_FALSE(HttpMessageParser::is_regular("sgn-CH-DE"));
	EXPECT_FALSE(HttpMessageParser::is_regular("\0"));
	EXPECT_FALSE(HttpMessageParser::is_regular("\0aa"));
}

TEST(TestHttpMessageParser, IsGrandfathered) {
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("en-GB-oed"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-ami"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-bnn"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-default"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-enochian"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-hak"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-klingon"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-lux"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-mingo"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-navajo"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-pwn"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-tao"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-tay"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("i-tsu"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("sgn-BE-FR"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("sgn-BE-NL"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("sgn-CH-DE"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("art-lojban"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("cel-gaulish"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("no-bok"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("no-nyn"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("zh-guoyu"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("zh-hakka"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("zh-min"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("zh-min-nan"));
	EXPECT_TRUE(HttpMessageParser::is_grandfathered("zh-xiang"));

	EXPECT_FALSE(HttpMessageParser::is_grandfathered(""));
	EXPECT_FALSE(HttpMessageParser::is_grandfathered("\0"));
	EXPECT_FALSE(HttpMessageParser::is_grandfathered("\0aa"));
	EXPECT_FALSE(HttpMessageParser::is_grandfathered("aaa"));
	EXPECT_FALSE(HttpMessageParser::is_grandfathered("EN-GB-OED"));  // todo: case-sensitive??
}

/*
 language      = 2*3ALPHA            ; shortest ISO 639 code
                 ["-" extlang]       ; sometimes followed by
                                     ; extended language subtags
               / 4ALPHA              ; or reserved for future use
               / 5*8ALPHA            ; or registered language subtag
 */
TEST(TestHttpMessageParser, IsLanguage) {
	EXPECT_TRUE(HttpMessageParser::is_language("en"));
	EXPECT_TRUE(HttpMessageParser::is_language("aaa"));
	EXPECT_TRUE(HttpMessageParser::is_language("xxx"));

	EXPECT_TRUE(HttpMessageParser::is_language("en-aaa"));
	EXPECT_TRUE(HttpMessageParser::is_language("en-aaa-bbb"));
	EXPECT_TRUE(HttpMessageParser::is_language("en-aaa-bbb-ccc"));

	EXPECT_TRUE(HttpMessageParser::is_language("aaaa"));
	EXPECT_TRUE(HttpMessageParser::is_language("aaaaa"));
	EXPECT_TRUE(HttpMessageParser::is_language("aaaaabbb"));

	EXPECT_FALSE(HttpMessageParser::is_language(""));
	EXPECT_FALSE(HttpMessageParser::is_language("a"));
	EXPECT_FALSE(HttpMessageParser::is_language("aa-"));
	EXPECT_FALSE(HttpMessageParser::is_language("aaaaabbbb"));
	EXPECT_FALSE(HttpMessageParser::is_language("a12"));
	EXPECT_FALSE(HttpMessageParser::is_language("abc123"));
	EXPECT_FALSE(HttpMessageParser::is_language(" "));
	EXPECT_FALSE(HttpMessageParser::is_language(" abc"));
	EXPECT_FALSE(HttpMessageParser::is_language("abc "));
	EXPECT_FALSE(HttpMessageParser::is_language(" abc "));
	EXPECT_FALSE(HttpMessageParser::is_language("en-aa"));
	EXPECT_FALSE(HttpMessageParser::is_language("en--aa"));
	EXPECT_FALSE(HttpMessageParser::is_language("en-aaa-"));
	EXPECT_FALSE(HttpMessageParser::is_language("en-aaa-b"));
	EXPECT_FALSE(HttpMessageParser::is_language("en-aaa-bbbb"));
	EXPECT_FALSE(HttpMessageParser::is_language("en-aaa-bbb-ccc-ddd"));
	EXPECT_FALSE(HttpMessageParser::is_language("\0"));
	EXPECT_FALSE(HttpMessageParser::is_language("\0aa"));
}

/*
 script = 4ALPHA ; ISO 15924 code
 */
TEST(TestHttpMessageParser, IsScript) {
	EXPECT_TRUE(HttpMessageParser::is_script("aaaa"));
	EXPECT_TRUE(HttpMessageParser::is_script("AAAA"));
	EXPECT_TRUE(HttpMessageParser::is_script("zzzz"));
	EXPECT_TRUE(HttpMessageParser::is_script("abcD"));

	EXPECT_FALSE(HttpMessageParser::is_script(""));
	EXPECT_FALSE(HttpMessageParser::is_script("    "));
	EXPECT_FALSE(HttpMessageParser::is_script("1234"));
	EXPECT_FALSE(HttpMessageParser::is_script("a"));
	EXPECT_FALSE(HttpMessageParser::is_script("aaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
	EXPECT_FALSE(HttpMessageParser::is_script("  a  "));
	EXPECT_FALSE(HttpMessageParser::is_script("\0"));
	EXPECT_FALSE(HttpMessageParser::is_script("\0aa"));
}

/*
 region        = 2ALPHA              ; ISO 3166-1 code
               / 3DIGIT              ; UN M.49 code
 */
TEST(TestHttpMessageParser, IsRegion) {
	EXPECT_TRUE(HttpMessageParser::is_region("aa"));
	EXPECT_TRUE(HttpMessageParser::is_region("bb"));
	EXPECT_TRUE(HttpMessageParser::is_region("123"));
	EXPECT_TRUE(HttpMessageParser::is_region("000"));
	EXPECT_TRUE(HttpMessageParser::is_region("999"));

	EXPECT_FALSE(HttpMessageParser::is_region(""));
	EXPECT_FALSE(HttpMessageParser::is_region("  "));
	EXPECT_FALSE(HttpMessageParser::is_region("+123"));
	EXPECT_FALSE(HttpMessageParser::is_region("12a"));
	EXPECT_FALSE(HttpMessageParser::is_region("1a"));
	EXPECT_FALSE(HttpMessageParser::is_region("+1"));
	EXPECT_FALSE(HttpMessageParser::is_region("+1"));
	EXPECT_FALSE(HttpMessageParser::is_region("1234"));
	EXPECT_FALSE(HttpMessageParser::is_region("1234-ab"));
	EXPECT_FALSE(HttpMessageParser::is_region(" ab"));
	EXPECT_FALSE(HttpMessageParser::is_region("ab "));
	EXPECT_FALSE(HttpMessageParser::is_region("\0"));
	EXPECT_FALSE(HttpMessageParser::is_region("\0aa"));
}

/*
 variant       = 5*8alphanum         ; registered variants
               / (DIGIT 3alphanum)
 */
TEST(TestHttpMessageParser, IsVariant) {
	EXPECT_TRUE(HttpMessageParser::is_variant("12345"));
	EXPECT_TRUE(HttpMessageParser::is_variant("12345678"));
	EXPECT_TRUE(HttpMessageParser::is_variant("aaaaa"));
	EXPECT_TRUE(HttpMessageParser::is_variant("aaaaa678"));

	EXPECT_TRUE(HttpMessageParser::is_variant("1234"));
	EXPECT_TRUE(HttpMessageParser::is_variant("1abc"));

	EXPECT_FALSE(HttpMessageParser::is_variant(""));
	EXPECT_FALSE(HttpMessageParser::is_variant("1234_678"));
	EXPECT_FALSE(HttpMessageParser::is_variant("aaaaabbbb"));
	EXPECT_FALSE(HttpMessageParser::is_variant("a b c d"));
	EXPECT_FALSE(HttpMessageParser::is_variant("abc''"));
	EXPECT_FALSE(HttpMessageParser::is_variant("\0"));
	EXPECT_FALSE(HttpMessageParser::is_variant("\0aa"));
}

/*
 extension     = singleton 1*("-" (2*8alphanum))
 singleton     = DIGIT               ; 0 - 9
               / %x41-57             ; A - W
               / %x59-5A             ; Y - Z
               / %x61-77             ; a - w
               / %x79-7A             ; y - z
 */
TEST(TestHttpMessageParser, IsExtension) {
	EXPECT_TRUE(HttpMessageParser::is_extension("0-12"));
	EXPECT_TRUE(HttpMessageParser::is_extension("0-123456"));
	EXPECT_TRUE(HttpMessageParser::is_extension("0-12345678"));
	EXPECT_TRUE(HttpMessageParser::is_extension("0-12345678-aa-bb-c12-hoge-huga"));


	EXPECT_FALSE(HttpMessageParser::is_extension(""));
	EXPECT_FALSE(HttpMessageParser::is_extension("0"));
	EXPECT_FALSE(HttpMessageParser::is_extension("0--a"));
	EXPECT_FALSE(HttpMessageParser::is_extension(" "));
	EXPECT_FALSE(HttpMessageParser::is_extension("x-12345"));
	EXPECT_FALSE(HttpMessageParser::is_extension("a-1"));
	EXPECT_FALSE(HttpMessageParser::is_extension("a-123456789"));
	EXPECT_FALSE(HttpMessageParser::is_extension("*-123456-aaaa"));
	EXPECT_FALSE(HttpMessageParser::is_extension("\0"));
	EXPECT_FALSE(HttpMessageParser::is_extension("\0aa"));
}

/*
 privateuse    = "x" 1*("-" (1*8alphanum))
 */
TEST(TestHttpMessageParser, IsPrivateuse) {
	EXPECT_TRUE(HttpMessageParser::is_privateuse("x-1"));
	EXPECT_TRUE(HttpMessageParser::is_privateuse("x-12345678"));
	EXPECT_TRUE(HttpMessageParser::is_privateuse("x-xxxxxxxx"));
	EXPECT_TRUE(HttpMessageParser::is_privateuse("x-12345678-a-b-c-d-e"));

	EXPECT_FALSE(HttpMessageParser::is_privateuse(""));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-,"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x--"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("xx"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("123-x"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-123456789"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-12345678-"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-12345678--"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("x-12345678-abcde-;"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("\0"));
	EXPECT_FALSE(HttpMessageParser::is_privateuse("\0aa"));
}

// ["-" OPTION]
TEST(TestHttpMessageParser, IsLangtagOption) {
	// script
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("-aaaa", 0,
													 HttpMessageParser::skip_script));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("aaaa", 0,
													  HttpMessageParser::skip_script));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 0,
													  HttpMessageParser::skip_script));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 1000,
													  HttpMessageParser::skip_script));

	// region
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("-aa", 0,
													 HttpMessageParser::skip_region));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("aa", 0,
													  HttpMessageParser::skip_region));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 0,
													  HttpMessageParser::skip_region));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 1000,
													  HttpMessageParser::skip_region));

	// variant
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("-1234", 0,
													 HttpMessageParser::skip_variant));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("1234", 0,
													  HttpMessageParser::skip_variant));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 0,
													  HttpMessageParser::skip_variant));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 1000,
													  HttpMessageParser::skip_variant));

	// extension
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("-0-12", 0,
													 HttpMessageParser::skip_extension));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("0-12", 0,
													  HttpMessageParser::skip_extension));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 0,
													  HttpMessageParser::skip_extension));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 1000,
													  HttpMessageParser::skip_extension));

	// privateuse
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("-x-12345678", 0,
													 HttpMessageParser::skip_privateuse));
	EXPECT_TRUE(HttpMessageParser::is_langtag_option("xxx-x-12345678", 3,
													 HttpMessageParser::skip_privateuse));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("x-12345678", 0,
													 HttpMessageParser::skip_privateuse));
	EXPECT_FALSE(HttpMessageParser::is_langtag_option("", 1000,
													 HttpMessageParser::skip_privateuse));
}

/*
 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]


 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]

 language      = 2*3ALPHA ["-" extlang]
                  / 4ALPHA / 5*8ALPHA
 extlang       = 3ALPHA *2("-" 3ALPHA)

 script        = 4ALPHA
 region        = 2ALPHA / 3DIGIT
 variant       = 5*8alphanum / (DIGIT 3alphanum)
 extension     = singleton 1*("-" (2*8alphanum))
 privateuse    = "x" 1*("-" (1*8alphanum))
 */
TEST(TestHttpMessageParser, IsLangtag) {
	EXPECT_TRUE(HttpMessageParser::is_langtag("en"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-aaaa"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-aa"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-12345-12345"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-0-123456-0-123456"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-x-1"));

	EXPECT_TRUE(HttpMessageParser::is_langtag("en-aaa-aa-x-1"));


	EXPECT_FALSE(HttpMessageParser::is_langtag(""));
	EXPECT_FALSE(HttpMessageParser::is_langtag("e-aaa"));
	EXPECT_FALSE(HttpMessageParser::is_langtag("en--aaa"));
	EXPECT_FALSE(HttpMessageParser::is_langtag("en-aaa--aa"));
	EXPECT_FALSE(HttpMessageParser::is_langtag("\0"));
	EXPECT_FALSE(HttpMessageParser::is_langtag("\0aa"));
}

TEST(TestHttpMessageParser, IsOpaqueTag) {
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"!\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"#\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"1\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"*\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"\\\""));
	EXPECT_TRUE(HttpMessageParser::is_opaque_tag("\"'\""));

	EXPECT_FALSE(HttpMessageParser::is_opaque_tag(""));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag("\""));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag(" "));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag("\t"));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag("\n"));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag("\0"));
	EXPECT_FALSE(HttpMessageParser::is_opaque_tag("\0aa"));
}

TEST(TestHttpMessageParser, IsEntityTag) {
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("W/\"\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("W/\"!\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("W/\"ABC\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("W/\"***\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("\"\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("\"!\""));
	EXPECT_TRUE(HttpMessageParser::is_entity_tag("\"ABC\""));


	EXPECT_FALSE(HttpMessageParser::is_entity_tag(""));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag(" "));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag("!"));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag("\"ABC SP NG\""));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag("W/\"ABC\tTAB\tIS\tNG\""));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag("\0"));
	EXPECT_FALSE(HttpMessageParser::is_entity_tag("\0aa"));
}

TEST(TestHttpMessageParser, IsQdtext) {
	EXPECT_TRUE(HttpMessageParser::is_qdtext('\t'));
	EXPECT_TRUE(HttpMessageParser::is_qdtext(' '));
	EXPECT_TRUE(HttpMessageParser::is_qdtext('!'));
	EXPECT_TRUE(HttpMessageParser::is_qdtext('~'));

	EXPECT_FALSE(HttpMessageParser::is_qdtext('"'));
	EXPECT_FALSE(HttpMessageParser::is_qdtext('\0'));
	EXPECT_FALSE(HttpMessageParser::is_qdtext('\r'));
	EXPECT_FALSE(HttpMessageParser::is_qdtext('\n'));
}

TEST(TestHttpMessageParser, IsHexDig) {
	EXPECT_TRUE(HttpMessageParser::is_hexdig('0'));
	EXPECT_TRUE(HttpMessageParser::is_hexdig('9'));
	EXPECT_TRUE(HttpMessageParser::is_hexdig('a'));
	EXPECT_TRUE(HttpMessageParser::is_hexdig('f'));
	EXPECT_TRUE(HttpMessageParser::is_hexdig('A'));
	EXPECT_TRUE(HttpMessageParser::is_hexdig('F'));

	EXPECT_FALSE(HttpMessageParser::is_hexdig('x'));
	EXPECT_FALSE(HttpMessageParser::is_hexdig('g'));
	EXPECT_FALSE(HttpMessageParser::is_hexdig('-'));
	EXPECT_FALSE(HttpMessageParser::is_hexdig('\0'));
	EXPECT_FALSE(HttpMessageParser::is_hexdig(' '));
	EXPECT_FALSE(HttpMessageParser::is_hexdig('\t'));
}

TEST(TestHttpMessageParser, IsAttrChar) {
	EXPECT_TRUE(HttpMessageParser::is_attr_char('a'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('z'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('0'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('9'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('!'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('#'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('$'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('&'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('+'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('-'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('.'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('^'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('_'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('`'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('|'));
	EXPECT_TRUE(HttpMessageParser::is_attr_char('~'));

	EXPECT_FALSE(HttpMessageParser::is_attr_char('\0'));
	EXPECT_FALSE(HttpMessageParser::is_attr_char('"'));
	EXPECT_FALSE(HttpMessageParser::is_attr_char('*'));
	EXPECT_FALSE(HttpMessageParser::is_attr_char('\''));
	EXPECT_FALSE(HttpMessageParser::is_attr_char('%'));
	EXPECT_FALSE(HttpMessageParser::is_attr_char(';'));
	EXPECT_FALSE(HttpMessageParser::is_attr_char(','));
	EXPECT_FALSE(HttpMessageParser::is_attr_char(' '));
	EXPECT_FALSE(HttpMessageParser::is_attr_char('\t'));
}

TEST(TestHttpMessageParser, IsUnreserved) {
	EXPECT_TRUE(HttpMessageParser::is_unreserved('a'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('A'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('0'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('9'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('-'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('.'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('_'));
	EXPECT_TRUE(HttpMessageParser::is_unreserved('~'));

	EXPECT_FALSE(HttpMessageParser::is_unreserved('\0'));
	EXPECT_FALSE(HttpMessageParser::is_unreserved(' '));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('\t'));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('\\'));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('\''));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('"'));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('\r'));
	EXPECT_FALSE(HttpMessageParser::is_unreserved('\n'));
}

TEST(TestHttpMessageParser, IsSubDelim) {
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('!'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('$'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('&'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('\''));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('('));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims(')'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('*'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('+'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims(','));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims(';'));
	EXPECT_TRUE(HttpMessageParser::is_sub_delims('='));

	EXPECT_FALSE(HttpMessageParser::is_sub_delims('\0'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('a'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('A'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('0'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('9'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims(' '));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('\t'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('\r'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('\n'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('_'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('^'));
	EXPECT_FALSE(HttpMessageParser::is_sub_delims('~'));
}

TEST(TestHttpMessageParser, IsDecOctet) {
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("0"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("1"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("9"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("10"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("99"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("100"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("199"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("200"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("249"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("250"));
	EXPECT_TRUE(HttpMessageParser::is_dec_octet("255"));

	EXPECT_FALSE(HttpMessageParser::is_dec_octet("00"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("000"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("01"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("256"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet(" 1"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("+1"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet(" 1.0"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("1.0"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet(""));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet(" "));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("999999999999999999"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("\r1"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("1\r"));
	EXPECT_FALSE(HttpMessageParser::is_dec_octet("1\n"));

	EXPECT_FALSE(HttpMessageParser::is_dec_octet("\0\0\0"));
}

TEST(TestHttpMessageParser, IsIPv4address) {
	EXPECT_TRUE(HttpMessageParser::is_ipv4address("0.0.0.0"));
	EXPECT_TRUE(HttpMessageParser::is_ipv4address("255.255.255.255"));

	EXPECT_FALSE(HttpMessageParser::is_ipv4address(""));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("\0"));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("\0aa"));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("0.0.0.0."));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("0.0.0.0.0"));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("0.0.0.0 "));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("a.b.c.d"));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("255.255.255.256"));
	EXPECT_FALSE(HttpMessageParser::is_ipv4address("00.00.00.00"));
}

TEST(TestHttpMessageParser, IsIPv6address) {
	EXPECT_TRUE(HttpMessageParser::is_ipv6address("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789"));
	EXPECT_TRUE(HttpMessageParser::is_ipv6address("abcd:ed01:2345:6789:abcd:ef01:2345:0000"));

	EXPECT_TRUE(HttpMessageParser::is_ipv6address("0:0:0:0:0:0:0:0"));
	// EXPECT_TRUE(HttpMessageParser::is_ipv6address("::"));
	EXPECT_TRUE(HttpMessageParser::is_ipv6address("0:0:0:0:0:0:0:1"));
	// EXPECT_TRUE(HttpMessageParser::is_ipv6address("::1"));
	EXPECT_TRUE(HttpMessageParser::is_ipv6address("FF01:0:0:0:0:0:0:101"));
	// EXPECT_TRUE(HttpMessageParser::is_ipv6address("FF01::101"));
	EXPECT_TRUE(HttpMessageParser::is_ipv6address("2001:DB8:0:0:8:800:200C:417A"));
	// EXPECT_TRUE(HttpMessageParser::is_ipv6address("2001:DB8::8:800:200C:417A"));


	EXPECT_FALSE(HttpMessageParser::is_ipv6address(""));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address("GGGG:EF01:2345:6789:ABCD:EF01:2345:6789"));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789:"));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789 "));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address(" ABCD:EF01:2345:6789:ABCD:EF01:2345:6789"));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address("ABCD.EF01.2345.6789.ABCD.EF01.2345.6789"));
	EXPECT_FALSE(HttpMessageParser::is_ipv6address("0.0.0.0"));
}

TEST(TestHttpMessageParser, IsIPvFuture) {
	EXPECT_TRUE(HttpMessageParser::is_ipvfuture("vA.a:b:c"));
	EXPECT_TRUE(HttpMessageParser::is_ipvfuture("v6.0"));
	EXPECT_TRUE(HttpMessageParser::is_ipvfuture("vF.:1:2:3:0"));

	EXPECT_FALSE(HttpMessageParser::is_ipvfuture(""));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("\0\0aaa"));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("a:b:c"));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("vv.a"));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("vA."));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("vA. "));
	EXPECT_FALSE(HttpMessageParser::is_ipvfuture("aA:::"));
}

TEST(TestHttpMessageParser, IsIpLiteral) {
	EXPECT_TRUE(HttpMessageParser::is_ip_literal("[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]"));
	EXPECT_TRUE(HttpMessageParser::is_ip_literal("[0:0:0:0:0:0:0:0]"));
	EXPECT_TRUE(HttpMessageParser::is_ip_literal("[2001:DB8:0:0:8:800:200C:417A]"));
	EXPECT_TRUE(HttpMessageParser::is_ip_literal("[vF.:1:2:3:0]"));

	EXPECT_FALSE(HttpMessageParser::is_ip_literal(""));
	EXPECT_FALSE(HttpMessageParser::is_ip_literal("[]"));
	EXPECT_FALSE(HttpMessageParser::is_ip_literal("\0\0aaa"));
}


TEST(TestHttpMessageParser, IsRegName) {
	EXPECT_TRUE(HttpMessageParser::is_reg_name("localhost"));
	EXPECT_TRUE(HttpMessageParser::is_reg_name("abc"));
	EXPECT_TRUE(HttpMessageParser::is_reg_name("123"));
	EXPECT_TRUE(HttpMessageParser::is_reg_name("%abc"));

	EXPECT_FALSE(HttpMessageParser::is_reg_name(""));
	EXPECT_FALSE(HttpMessageParser::is_reg_name("[]"));
	EXPECT_FALSE(HttpMessageParser::is_reg_name("\0\0aaa"));
}

TEST(TestHttpMessageParser, IsValidUriHost) {
	EXPECT_TRUE(HttpMessageParser::is_valid_uri_host("example.com"));
	EXPECT_TRUE(HttpMessageParser::is_valid_uri_host("127.0.0.1"));
	EXPECT_TRUE(HttpMessageParser::is_valid_uri_host("255.255.255.255"));
	EXPECT_TRUE(HttpMessageParser::is_valid_uri_host("[ABCD:EF01:2345:6789:ABCD:EF01:2345:6789]"));
	EXPECT_TRUE(HttpMessageParser::is_valid_uri_host("localhost"));

	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host(" example.com "));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host(" example.com: "));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host("  "));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host(" : "));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host(" 127.0.0 "));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host("[]"));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host("[localhost]"));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host("[127.0.0.1]"));
	EXPECT_FALSE(HttpMessageParser::is_valid_uri_host("ABCD:EF01:2345:6789:ABCD:EF01:2345:6789"));
}

TEST(TestHttpMessageParser, IsValidPort) {
	EXPECT_TRUE(HttpMessageParser::is_valid_port("0"));
	EXPECT_TRUE(HttpMessageParser::is_valid_port("1"));
	EXPECT_TRUE(HttpMessageParser::is_valid_port("10"));
	EXPECT_TRUE(HttpMessageParser::is_valid_port("0001"));
	EXPECT_TRUE(HttpMessageParser::is_valid_port("8080"));
	EXPECT_TRUE(HttpMessageParser::is_valid_port("65535"));

	EXPECT_FALSE(HttpMessageParser::is_valid_port(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_port(" 1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("1 "));
	EXPECT_FALSE(HttpMessageParser::is_valid_port(" 1 "));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("-1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("+1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("65536"));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("2147483647"));
	EXPECT_FALSE(HttpMessageParser::is_valid_port("2147483648"));
}

TEST(TestHttpMessageParser, IsValidScheme) {
	EXPECT_TRUE(HttpMessageParser::is_valid_scheme("a"));
	EXPECT_TRUE(HttpMessageParser::is_valid_scheme("a+-."));
	EXPECT_TRUE(HttpMessageParser::is_valid_scheme("aaaaaa"));
	EXPECT_TRUE(HttpMessageParser::is_valid_scheme("ABC+-DE.F"));
	EXPECT_TRUE(HttpMessageParser::is_valid_scheme("a01234"));

	EXPECT_FALSE(HttpMessageParser::is_valid_scheme(""));
	EXPECT_FALSE(HttpMessageParser::is_valid_scheme("1"));
	EXPECT_FALSE(HttpMessageParser::is_valid_scheme("1abc"));
	EXPECT_FALSE(HttpMessageParser::is_valid_scheme("a_*"));
	EXPECT_FALSE(HttpMessageParser::is_valid_scheme("\0"));
}

//TEST(TestHttpMessageParser, ) {
//	EXPECT_TRUE(HttpMessageParser::);
//
//	EXPECT_FALSE(HttpMessageParser::);
//}

//TEST(TestHttpMessageParser, ) {
//	EXPECT_TRUE(HttpMessageParser::);
//
//	EXPECT_FALSE(HttpMessageParser::);
//}

//TEST(TestHttpMessageParser, ) {
//	EXPECT_TRUE(HttpMessageParser::);
//
//	EXPECT_FALSE(HttpMessageParser::);
//}

//TEST(TestHttpMessageParser, ) {
//	EXPECT_TRUE(HttpMessageParser::);
//
//	EXPECT_FALSE(HttpMessageParser::);
//}

