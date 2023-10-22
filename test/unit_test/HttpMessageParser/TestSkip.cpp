#include <climits>
#include "HttpMessageParser.hpp"
#include "gtest/gtest.h"

TEST(TestHttpMessageParser, SkipQuotedString) {
	std::size_t end;
	std::string str;

	str = "\"abc\"";
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

/*
 langtag       = language
                 ["-" script]
                 ["-" region]
                 *("-" variant)
                 *("-" extension)
                 ["-" privateuse]
 */
TEST(TestHttpMessageParser, SkipLanguage) {
	std::size_t end;
	std::string str;

	str = "aa";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaaa";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaaaabbb";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "0123aa";
	HttpMessageParser::skip_language(str, 4, &end);
	EXPECT_EQ(str.length(), end);

	str = "0123aaaaabbbb";
	//     01234567890123
	HttpMessageParser::skip_language(str, 4, &end);
	EXPECT_EQ(4, end);

	str = "LintTooLong";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "123";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	HttpMessageParser::skip_language(str, 10, &end);
	EXPECT_EQ(10, end);

	str = "aaa";
	HttpMessageParser::skip_language(str, 100000, &end);
	EXPECT_EQ(100000, end);

	str = "aa-";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(2, end);

	str = "aa-bbb";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aa-ngng";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(2, end);

	str = "aa-ngng";
	HttpMessageParser::skip_language(str, str.length(), &end);
	EXPECT_EQ(str.length(), end);

	str = "aa-bbb-CCC";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aa-bbb-CCC-DDD";
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aa-bbb-CCC-MAX";
	//     012345678901234
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(14, end);

	str = "aa-bbb-CCC-DDD-";
	//     012345678901234
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(14, end);

	str = "aa-bbb-CCC-DDD-DoNotReadHere";
	//     012345678901234
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(14, end);

	str = "aa-bbb-CCC-ThisIsNgPart";
	//     012345678901234
	HttpMessageParser::skip_language(str, 0, &end);
	EXPECT_EQ(10, end);

}

TEST(TestHttpMessageParser, SkipScript) {
	std::size_t end;
	std::string str;

	str = "abcd";
	HttpMessageParser::skip_script(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "hoge-abcd";
	//     012345678
	HttpMessageParser::skip_script(str, 5, &end);
	EXPECT_EQ(str.length(), end);

	str = "abcde";
	//     012345678
	HttpMessageParser::skip_script(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	//     012345678
	HttpMessageParser::skip_script(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "abcd";
	//     012345678
	HttpMessageParser::skip_script(str, 1000, &end);
	EXPECT_EQ(1000, end);

	str = "abcd-1234";
	//     012345678
	HttpMessageParser::skip_script(str, 0, &end);
	EXPECT_EQ(4, end);

	str = "12-abcd-x";
	//     012345678
	HttpMessageParser::skip_script(str, 3, &end);
	EXPECT_EQ(7, end);
}

TEST(TestHttpMessageParser, SkipRegion) {
	std::size_t end;
	std::string str;

	str = "aa";
	HttpMessageParser::skip_region(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "a";
	HttpMessageParser::skip_region(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "aaa";
	HttpMessageParser::skip_region(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "012";
	HttpMessageParser::skip_region(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aa-";
	//     01234567890
	HttpMessageParser::skip_region(str, 0, &end);
	EXPECT_EQ(2, end);

	str = "aa-012-xxxx";
	//     01234567890
	HttpMessageParser::skip_region(str, 3, &end);
	EXPECT_EQ(6, end);
}

TEST(TestHttpMessageParser, SkipVariant) {
	std::size_t end;
	std::string str;

	str = "12345";
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "1234";
	//     01234567890
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(4, end);

	str = "1abc";
	//     01234567890
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(4, end);

	str = "aaaa";
	//     01234567890
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "123456789";
	//     01234567890
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "aaa-12345-x";
	//     01234567890
	HttpMessageParser::skip_variant(str, 4, &end);
	EXPECT_EQ(9, end);

	str = "";
	//     01234567890
	HttpMessageParser::skip_variant(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "";
	//     01234567890
	HttpMessageParser::skip_variant(str, 10, &end);
	EXPECT_EQ(10, end);

}

TEST(TestHttpMessageParser, SkipExtension) {
	std::size_t end;
	std::string str;

	str = "a-12";
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "a-12-123-1234-12345";
	//     012345678901234567890
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "a-12-123-1234-123456789";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(13, end);

	str = "a--12-123-1234-123456789";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "x-12-123-1234";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "aa-12-123-1234-123456789";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "a";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "a-***";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "xxx-a-12-123-1234-ThisIsNgPart";
	//     01234567890123456789012
	HttpMessageParser::skip_extension(str, 4, &end);
	EXPECT_EQ(17, end);
}

TEST(TestHttpMessageParser, SkipPrivateuse) {
	std::size_t end;
	std::string str;

	str = "x-1";
	HttpMessageParser::skip_privateuse(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "x-12345678";
	HttpMessageParser::skip_privateuse(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "x-123456789";
	HttpMessageParser::skip_privateuse(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "x-";
	HttpMessageParser::skip_privateuse(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "x-**";
	HttpMessageParser::skip_privateuse(str, 0, &end);
	EXPECT_EQ(0, end);

	str = "abc-x-123--";
	//     01234567890123456789012
	HttpMessageParser::skip_privateuse(str, 4, &end);
	EXPECT_EQ(9, end);

	str = "";
	//     01234567890123456789012
	HttpMessageParser::skip_privateuse(str, 10, &end);
	EXPECT_EQ(10, end);

}

/*
 langtag       = language ["-" extlang]	// a [b]
                 ["-" script]			// c
                 ["-" region]			// d
                 *("-" variant)			// e
                 *("-" extension)		// f
                 ["-" privateuse]		// g
 */
TEST(TestHttpMessageParser, SkipLangtag) {
	std::size_t end;

	std::string str;

	str = "aa";
	//                 aa
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa-aaa";
	//     aaa bbb
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa-aaa-aaa-aaa";
	//     aaa bbb-bbb-bbb
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC";
	//     aaa bbb-bbb-bbb cccc
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-DD";
	//     aaa bbb-bbb-bbb cccc dd
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123";
	//     aaa bbb-bbb-bbb cccc ddd
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345";
	//     aaa bbb-bbb-bbb cccc ddd eeeee
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345678";
	//     aaa bbb-bbb-bbb cccc ddd eeeeeeee
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345-1abc-aaaa1234";
	//     aaa bbb-bbb-bbb cccc ddd eeeee-eeee-eeeeeeee
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345-a-12";
	//     aaa bbb-bbb-bbb cccc ddd eeeee f-ff
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345-a-12-1234bbbb-1212";
	//     aaa bbb-bbb-bbb cccc ddd eeeee f-ff-ffffffff-ffff
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345-a-12-1234bbbb-1212-x-1";
	//     aaa bbb-bbb-bbb cccc ddd eeeee f-ff-ffffffff-ffff g-g
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBB-CCCC-123-12345-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa bbb-bbb-bbb cccc ddd eeeee f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-CCCC-123-12345-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa cccc ddd eeeee f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-CCCC";
	//     aaa cccc
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-123-12345-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa ddd eeeee f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-123";
	//     aaa ddd
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-12345-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa eeeee f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-12345";
	//     aaa eeeee
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-a-12";
	//     aaa f-ff
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-x-12345678-aaaa-12ab";
	//     aaa g-gggggggg-gggg-gggg
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "AAA-BBB-BBB-BBBBB-CCCC-123-12345-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	//     aaa bbb-bbb-bbb^^ cccc ddd eeeee f-ff-ffffffff-ffff g-gggggggg-gggg-gggg
	//     012345678901234567890
	//     B ng, but E OK...
	//     expect 11 -> actual 17
	HttpMessageParser::skip_langtag(str, 0, &end);
	EXPECT_EQ(17, end);
}

TEST(TestHttpMessageParser, SkipLangage_tag) {
	std::size_t end;
	std::string str;

	str = "AAA-a-12-1234bbbb-1212-x-12345678-aaaa-12ab";
	HttpMessageParser::skip_language_tag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "x-12345678";
	//     012345678901234567890
	HttpMessageParser::skip_language_tag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "x-12345678-****";
	//     012345678901234567890
	HttpMessageParser::skip_language_tag(str, 0, &end);
	EXPECT_EQ(10, end);

	str = "en-GB-oed";
	//     012345678901234567890
	HttpMessageParser::skip_language_tag(str, 0, &end);
	EXPECT_EQ(str.length(), end);

	str = "en-GB-oed;xxxxxxx";
	//              ^ todo: delimiter...
	//     012345678901234567890
	HttpMessageParser::skip_language_tag(str, 0, &end);
	EXPECT_EQ(9, end);
}

TEST(TestHttpMessageParser, SkipOWS) {
	std::size_t pos;
	std::string str;

	str = " 123";
	pos = 0;
	HttpMessageParser::skip_ows(str, &pos);
	EXPECT_EQ(1, pos);

	str = "            ";
	pos = 0;
	HttpMessageParser::skip_ows(str, &pos);
	EXPECT_EQ(str.length(), pos);

	str = "            ";
	pos = 3;
	HttpMessageParser::skip_ows(str, &pos);
	EXPECT_EQ(str.length(), pos);

	str = "            ";
	pos = str.length();
	HttpMessageParser::skip_ows(str, &pos);
	EXPECT_EQ(str.length(), pos);

	str = "";
	pos = 3;
	HttpMessageParser::skip_ows(str, &pos);
	EXPECT_EQ(3, pos);
}

TEST(TestHttpMessageParser, SkipQuotedpair) {
	std::size_t pos, end;
	std::string str;

	str = "\\\t";
	pos = 0;
	HttpMessageParser::skip_quoted_pair(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "\\ aaaaa";
	pos = 0;
	HttpMessageParser::skip_quoted_pair(str, pos, &end);
	EXPECT_EQ(2, end);

	str = "aaaaaaaa";
	pos = 0;
	HttpMessageParser::skip_quoted_pair(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "            ";
	pos = 0;
	HttpMessageParser::skip_quoted_pair(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "";
	pos = 10;
	HttpMessageParser::skip_quoted_pair(str, pos, &end);
	EXPECT_EQ(10, end);
}

// comment = "(" *( ctext / quoted-pair / comment ) ")"
TEST(TestHttpMessageParser, SkipComment) {
	std::size_t pos, end;
	std::string str;

	str = "(abc)";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "(this is comment)";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "this is comment";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "((abc))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "(((abc(def))))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "(((abc(def) )))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "(((abc(def)(hoge) )))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "(((abc(def)\t(hoge) )))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "()";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "(aaaa()(aa))";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "(((((";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "(";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "())";
	pos = 0;
	HttpMessageParser::skip_comment(str, pos, &end);
	EXPECT_EQ(0, end);
}

TEST(TestHttpMessageParser, SkipProduct) {
	std::size_t pos, end;
	std::string str;

	str = "a";
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "a/b";
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc/abc";
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "a,b";
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "a b";
	//     01234
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "a/b/c";
	//     01234
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "a/";
	//     01234
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "a///b";
	//     01234
	pos = 0;
	HttpMessageParser::skip_product(str, pos, &end);
	EXPECT_EQ(0, end);
}

TEST(TestHttpMessageParser, SkipRegName) {
	std::size_t pos, end;
	std::string str;

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "123";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "%ab";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc";
	//     012345678901234567890
	pos = 2;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc";
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "abc";
	//     012345678901234567890
	pos = 4;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "abc";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 1;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 2;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "!$&'()*+,;=abc123-._~%12";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "!$&'()*+,;=abc123-._~%12";
	//     012345678901234567890
	pos = 5;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "!$&'()*+,;=abc123-._~%%";
	//                          ^^ng
	//     012345678901234567890123
	pos = 0;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(21, end);

	str = "!$&'()*+,;=abc123-._~%%";
	//                          ^^ng
	//     012345678901234567890123
	pos = 21;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "!$&'()*+,;=abc123-._~%%";
	//                          ^^ng
	//     012345678901234567890123
	pos = 22;
	HttpMessageParser::skip_reg_name(str, pos, &end);
	EXPECT_EQ(pos, end);

}

TEST(TestHttpMessageParser, SkipIPv4address) {
	std::size_t pos, end;
	std::string str;

	str = "0.0.0.0";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "0.0.0.255";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "1.2.3.9";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "255.255.255.255";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "192.168.0.1";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "0.0.0.00";
	//           ^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "255.255.255.256";
	//                 ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "255.255.255.255.";
	//                    ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(15, end);

	str = "255,255,255,256";
	//        ^   ^   ^ ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "01.255.255.255";
	//     ^^ ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "123.234.345.456";
	//             ^^^ ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "";
	//    ^ ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "...";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "0.0.0.";
	//           ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

	str = " . . . ";
	//     ^ ^ ^ ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipv4address(str, pos, &end);
	EXPECT_EQ(0, end);

}

TEST(TestHttpMessageParser, SkipIPvFuture) {
	std::size_t pos, end;
	std::string str;

	str = "vF.0:1:2";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "vF.0:1:2 ";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(8, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "vA.";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "\0\0\0aaaaa";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "\0\0\0\0\0";
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_ipvfuture(str, pos, &end);
	EXPECT_EQ(pos, end);
}

TEST(TestHttpMessageParser, SkipH16) {
	std::size_t pos, end;
	std::string str;

	str = "0";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "0000";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "000011";
	//         ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(4, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "    ";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "ffg";
	//       ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_h16(str, pos, &end);
	EXPECT_EQ(2, end);

}

TEST(TestHttpMessageParser, SKipLs32) {
	std::size_t pos, end;
	std::string str;

	str = "0:1";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "0000:1111";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abcd:ef01:";
	//              ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(9, end);

	str = "0.0.0.0";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = ":";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "abcd:efgh";
	//            ^^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(7, end);


	str = "\0\0\0";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_ls32(str, pos, &end);
	EXPECT_EQ(pos, end);

}

TEST(TestHttpMessageParser, SkipScheme) {
	std::size_t pos, end;
	std::string str;

	str = "a";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "a01234";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "a01234*";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(6, end);

	str = "a_";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_scheme(str, pos, &end);
	EXPECT_EQ(pos, end);

}

TEST(TestHttpMessageParser, SkipPctEncoded) {
	std::size_t pos, end;
	std::string str;

	str = "%12";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "%12%12";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "%123";
	//        ^end
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "%12%";
	//        ^end
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "%12%3";
	//        ^end
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%1";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%%%%%";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%%%1";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 1000;
	HttpMessageParser::skip_pct_encoded(str, pos, &end);
	EXPECT_EQ(pos, end);


}

TEST(TestHttpMessageParser, SkipPchar) {
	std::size_t pos, end;
	std::string str;

	str = "123";
	//     ^^^ pchar
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pchar(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "abc";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pchar(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "-._~!$&'()*+,;=:@";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pchar(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "-._~!$&'()*+,;=:@  aaa";
	//                      ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pchar(str, pos, &end);
	EXPECT_EQ(1, end);

	str = " -._~!$&'()*+,;=:@";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_pchar(str, pos, &end);
	EXPECT_EQ(pos, end);

}

TEST(TestHttpMessageParser, SkipSegment) {
	std::size_t pos, end;
	std::string str;

	str = "123";
	//     ^^^ pchar
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "-._~!$&'()*+,;=:@";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "-._~!$&'()*+,;=:@  aaa";
	//                      ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment(str, pos, &end);
	EXPECT_EQ(17, end);

	str = " -._~!$&'()*+,;=:@";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment(str, pos, &end);
	EXPECT_EQ(pos, end);
}

TEST(TestHttpMessageParser, SkipSegmentNz) {
	std::size_t pos, end;
	std::string str;

	str = "aaa";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa123!$&'()*+,;=-._~";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa123!$&'()*+,;=-._~";
	//     012345678901234567890
	pos = 5;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "  \t";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%f";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%fg";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%ab%f";
	//        ^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "%ab%fg";
	//        ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz(str, pos, &end);
	EXPECT_EQ(3, end);
}

TEST(TestHttpMessageParser, SkipPathAbsoluteSegmentNzNc) {
	std::size_t pos, end;
	std::string str;

	str = "abc!$&'()*+,;=-._~";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "abc!$&'()*+,;=-._~";
	//     012345678901234567890
	pos = 5;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "%12%23";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = " ";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%fg";
	//       ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "aaa%fg";
	//        ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_segment_nz_nc(str, pos, &end);
	EXPECT_EQ(3, end);

}


TEST(TestHttpMessageParser, SkipQuery) {
	std::size_t pos, end;
	std::string str;

	str = "abc?/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "%12///////ok";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "";
	//     012345678901234567890
	pos = 10;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%%%%%%";
	//      ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "%1g";
	//       ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = " ";
	//     ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "\t\r\n";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_query(str, pos, &end);
	EXPECT_EQ(pos, end);
}

TEST(TestHttpMessageParser, SkipPathAbempty) {
	std::size_t pos, end;
	std::string str;

	str = "/abc";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/abc/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/////";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_path_abempty(str, pos, &end);
	EXPECT_EQ(pos, end);
}

TEST(TestHttpMessageParser, SkipPathAbsolute) {
	std::size_t pos, end;
	std::string str;

	str = "/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/abc:@/def";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//////aa////bb/cccc";
	//      ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "/ ";
	//      ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(1, end);

	str = "/a///";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/abc/%fg";
	//          ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(5, end);

	str = "//abc/%fg";
	//      ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_absolute(str, pos, &end);
	EXPECT_EQ(1, end);
}

TEST(TestHttpMessageParser, SkipPathNoscheme) {
	std::size_t pos, end;
	std::string str;

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_noscheme(str, pos, &end);
	EXPECT_EQ(str.length(), end);
}

TEST(TestHttpMessageParser, SkipPathRootless) {
	std::size_t pos, end;
	std::string str;

	str = "aaa";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa/bbb//c./d";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa/a/b////";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa/.";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/abc";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "/./abc";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_path_rootless(str, pos, &end);
	EXPECT_EQ(0, end);

}

TEST(TestHttpMessageParser, SkipUserInfo) {
	std::size_t pos, end;
	std::string str;

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaaabbb123%12";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "12:%ff12%12:!&?*";
	//                   ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(14, end);

	str = " aaa";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(0, end);

	str = "%12/aaa/bbb";
	//        ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(3, end);

	str = "a";
	//     012345678901234567890
	pos = 10;
	HttpMessageParser::skip_userinfo(str, pos, &end);
	EXPECT_EQ(pos, end);
}

TEST(TestHttpMessageParser, SkipAuthority) {
	std::size_t pos, end;
	std::string str;

	str = "localhost";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_authority(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "userinfo@localhost:8080";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_authority(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_authority(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "";
	//     012345678901234567890
	pos = 10;
	HttpMessageParser::skip_authority(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "localhost ";
	//              ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_authority(str, pos, &end);
	EXPECT_EQ(9, end);
}

TEST(TestHttpMessageParser, SkipRelativePart) {
	std::size_t pos, end;
	std::string str;

	// "//" authority path-abempty
	str = "//localhost:8080";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//localhost:8080/abc/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//localhost//////////";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//localhost:8080?";
	//                     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(16, end);

	str = "///localhost:8080?";
	//     ^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(0, end);

	// path-absolute
	str = "/localhost";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "/a/b/c////d";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	// path-rootless
	str = "a/b/c////d";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "localhost/hoge/huga%12%fg";
	//                           ^^^ng
	//     01234567890123456789012345
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(22, end);

	// path-empty
	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "^abc";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "?0123";
	//     ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "????0123";
	//       ^start = end
	//     012345678901234567890
	pos = 2;
	HttpMessageParser::skip_relative_part(str, pos, &end);
	EXPECT_EQ(pos, end);

}

TEST(TestHttpMessageParser, SkipHierPart) {
	std::size_t pos, end;
	std::string str;

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_hier_part(str, pos, &end);
	EXPECT_EQ(str.length(), end);
}

TEST(TestHttpMessageParser, SkipPartialURI) {
	std::size_t pos, end;
	std::string str;

	str = "//localhost";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//localhost:8080?a/b/c/";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "//a:8080?aaa^";
	//                 ^end
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(12, end);

	str = "//a:8080?aaa^";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "?/?/?/?\n";
	//            ^end
	//     012345678901234567890
	pos = 2;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(7, end);

	str = "//";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_partial_uri(str, pos, &end);
	EXPECT_EQ(0, end);
}

TEST(TestHttpMessageParser, SkipAbsoluteURI) {
	std::size_t pos, end;
	std::string str;

	str = "aaa://aaa@localhost:8080?get/abc???";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_absolute_uri(str, pos, &end);
	EXPECT_EQ(str.length(), end);

	str = "aaa://aaa@localhost%fg";
	//                        ^^^ng
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_absolute_uri(str, pos, &end);
	EXPECT_EQ(19, end);

	str = "";
	//     012345678901234567890
	pos = 0;
	HttpMessageParser::skip_absolute_uri(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "     ";
	//     012345678901234567890
	pos = 3;
	HttpMessageParser::skip_absolute_uri(str, pos, &end);
	EXPECT_EQ(pos, end);

	str = "   ";
	//     012345678901234567890
	pos = 100;
	HttpMessageParser::skip_absolute_uri(str, pos, &end);
	EXPECT_EQ(pos, end);
}

// TEST(TestHttpMessageParser, ) {
// 	std::size_t pos, end;
// 	std::string str;
//
// 	str = "";
// 	//     012345678901234567890
// 	pos = 0;
// 	HttpMessageParser::skip_(str, pos, &end);
// 	EXPECT_EQ(str.length(), end);
// }

// TEST(TestHttpMessageParser, ) {
// 	std::size_t pos, end;
// 	std::string str;
//
// 	str = "";
// 	//     012345678901234567890
// 	pos = 0;
// 	HttpMessageParser::skip_(str, pos, &end);
// 	EXPECT_EQ(str.length(), end);
// }

// TEST(TestHttpMessageParser, ) {
// 	std::size_t pos, end;
// 	std::string str;
//
// 	str = "";
// 	//     012345678901234567890
// 	pos = 0;
// 	HttpMessageParser::skip_(str, pos, &end);
// 	EXPECT_EQ(str.length(), end);
// }

