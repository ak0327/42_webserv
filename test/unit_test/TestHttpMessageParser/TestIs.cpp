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
	EXPECT_FALSE(HttpMessageParser::is_irregular("zh-xiang"));}

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

