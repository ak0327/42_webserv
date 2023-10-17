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

// TEST(TestHttpMessageParser, ) {
// }

// TEST(TestHttpMessageParser, ) {
// }

// TEST(TestHttpMessageParser, ) {
// }

