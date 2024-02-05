#include <iomanip>
#include "Constant.hpp"
#include "Color.hpp"
#include "FileHandler.hpp"
#include "Token.hpp"
#include "Tokenizer.hpp"
#include "gtest/gtest.h"

namespace {


#ifdef DEBUG
std::ostream &operator<<(std::ostream &out, const std::deque<std::string> &deque) {
	std::deque<std::string>::const_iterator itr;
	for (itr = deque.begin(); itr != deque.end(); ++itr) {
		out << GRAY << "[" << CYAN << *itr << GRAY << "]" << RESET;
	}
	return out;
}
#endif


void print_split(int test_no, const std::deque<std::string> &deque) {
#ifdef DEBUG
	std::cout << CYAN << "TEST No." << test_no++ << " : " << RESET << std::endl;
	std::cout << deque << std::endl;
#else
	(void)test_no;
	(void)deque;
#endif
}


void print_tokens(Tokenizer &tokenizer){
#ifdef DEBUG
	std::cout << tokenizer << std::endl;
#else
	(void)tokenizer;
#endif
}


void print_error_msg(Result<int, std::string> result, std::size_t line){
#ifdef DEBUG
	if (!result.is_err()) {
		FAIL() << " result is not error at L:" << line << std::endl;
	}
	std::string error_msg = result.get_err_value();
	std::cout << YELLOW << "error_msg: " << error_msg << RESET << std::endl;
#else
	(void)result;
	(void)line;
#endif
}


void expect_eq_tokens(const std::deque<Token> &expected,
					  const std::deque<Token> &actual,
					  std::size_t line) {
	EXPECT_EQ(expected.size(), actual.size());
	if (expected.size() != actual.size()) {
		FAIL();
	}
	for (std::size_t i = 0; i < expected.size(); ++i) {
		std::string expected_token, actual_token;

		expected_token = Token::get_token_output(expected[i], false);
		actual_token = Token::get_token_output(actual[i], false);
		EXPECT_EQ(expected_token, actual_token) << "  at L:" << line << std::endl;
	}
}


}  // namespace


////////////////////////////////////////////////////////////////////////////////


TEST(TestTokenizer, SplitStringNotKeepDelimiter) {
	Tokenizer tokenizer;
	bool is_keeping_delimiter = false;
	int test_no = 1;

	std::string data;
	std::deque<std::string> expected, actual;

	data	 = "a b c";
	//           ^ ^
	expected = {"a", "b", "c"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "a\nb\nc\n";
	//           ^^ ^^ ^^
	expected = {"a", "b", "c"};
	actual = Tokenizer::split_by_delimiter(data, LF, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "a";
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "a ";
	//           ^
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = " a";
	//          ^
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = " a ";
	//          ^ ^
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = " ";
	//          ^
	expected = {};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "";
	expected = {};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "\n   \n";
	//            ^^^
	expected = {"\n", "\n"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = " a  b  \n c ";
	//          ^ ^^ ^^  ^ ^ SP
	//                 ^^    LF
	expected = {"a", "b", "c"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);
	actual = Tokenizer::split_by_delimiter(actual, LF, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "a  b  c";
	expected = {"a  b  c"};
	actual = Tokenizer::split_by_delimiter(data, '\0', is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "";
	expected = {};
	actual = Tokenizer::split_by_delimiter(data, '\0', is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);}


TEST(TestTokenizer, SplitStringKeepDelimiter) {
	Tokenizer tokenizer;
	bool is_keeping_delimiter = true;
	int test_no = 1;

	std::string data;
	std::deque<std::string> expected, actual;

	data 	 = "a";
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = "a;";
	//           ^
	expected = {"a", ";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = "a;b;c;";
	//           ^ ^ ^
	expected = {"a", ";", "b", ";", "c", ";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = ";";
	//          ^
	expected = {";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = "  ;  ";
	//            ^
	expected = {"  ", ";", "  "};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = ";;;";
	//          ^^^
	expected = {";", ";", ";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = "";
	expected = {};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = "a";
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data	 = ";a;";
	//          ^ ^
	expected = {";", "a", ";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);}


TEST(TestTokenizer, SplitDequeNotKeepDelimiter) {
	Tokenizer tokenizer;
	bool is_keeping_delimiter = false;
	int test_no = 1;

	std::deque<std::string> data, expected, actual;

	data     = {"a"};
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);
	actual = Tokenizer::split_by_delimiter(actual, LF, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = {"a b", "  c  ", "", "   ", "d\n"};
	//            ^     ^^ ^^        ^^^         SP
	//                                       ^^  LF
	expected = {"a", "b", "c", "d"};
	actual = Tokenizer::split_by_delimiter(data, SP, is_keeping_delimiter);
	actual = Tokenizer::split_by_delimiter(actual, LF, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);}


TEST(TestTokenizer, SplitDequeKeepDelimiter) {
	Tokenizer tokenizer;
	bool is_keeping_delimiter = true;
	int test_no = 1;

	std::deque<std::string> data, expected, actual;

	data     = {"a"};
	expected = {"a"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	data	 = {"a;b", "  c;  ", "", ";"};
	//            ^        ^
	expected = {"a", ";", "b", "  c", ";", "  ", ";"};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
	////////////////////////////////////////////////////////////////////////////

	data = {
			"server", "{",
			"listen", "80", "default_server;",
			//                             ^
			"server_name", "_;",
			//               ^
			"}"
	};
	expected = {
			"server", "{",
			"listen", "80", "default_server", ";",
			"server_name", "_", ";",
			"}"
	};
	actual = Tokenizer::split_by_delimiter(data, SEMICOLON, is_keeping_delimiter);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);}


TEST(TestTokenizer, SplitData) {
	Tokenizer tokenizer;

	int test_no = 1;

	const char *conf_path1 = "test/test_conf/ok/ok1.conf";
	FileHandler file_handler1(conf_path1, CONFIG_FILE_EXTENSION);
	std::string data = file_handler1.get_contents();

	std::deque<std::string> expected, actual;

	expected = {
			"events", "{", "\n",
			"}", "\n",
			"\n",
			"http", "{", "\n",
			"}",
	};
	actual = Tokenizer::split_data(data);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path2 = "test/test_conf/ok/ok6.conf";
	FileHandler file_handler2(conf_path2, CONFIG_FILE_EXTENSION);
	data = file_handler2.get_contents();

	expected = {
			"events", "{", "\n",
			"}", "\n",
			"\n",
			"http", "{", "\n",
			"server", "{", "\n",
			"listen", "80", ";", "\n",
			"server_name", "example.com", "www.example.com", ";", "\n",
			"\n",
			"root", "/var/www/html", ";", "\n",
			"}", "\n",
			"\n",
			"location", "/some-directory/", "{", "\n",
			"autoindex", "on", ";", "\n",
			"}", "\n",
			"\n",
			"location", "/uploads", "{", "\n",
			"client_max_body_size", "20M", ";", "\n",
									  "root", "/path/to/upload/directory", ";", "\n",
			"}", "\n",
			"}",
	};
	actual = Tokenizer::split_data(data);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path3 = "test/test_conf/ng/empty.conf";
	FileHandler file_handler3(conf_path3, CONFIG_FILE_EXTENSION);
	data = file_handler3.get_contents();

	expected = {};
	actual = Tokenizer::split_data(data);

	EXPECT_EQ(expected, actual);

	print_split(test_no++, actual);
}



TEST(TestTokenizer, TestTokenizerValidationOK) {
	const char *conf_path_1 = "test/test_conf/ok/ok1.conf";
	FileHandler file_handler_1(conf_path_1, CONFIG_FILE_EXTENSION);

	std::string data;
	Tokenizer tokenizer;
	std::deque<Token> expected, actual;
	Result<int, std::string> result;

	data = file_handler_1.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 		kTokenKindBraces, 		1));
	expected.push_back(Token("}", 		kTokenKindBraces, 		2));
	expected.push_back(Token("http", 		kTokenKindBlockName, 	4));
	expected.push_back(Token("{", 		kTokenKindBraces, 		4));
	expected.push_back(Token("}", 		kTokenKindBraces, 		5));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_2 = "test/test_conf/ok/ok6.conf";
	FileHandler file_handler_2(conf_path_2, CONFIG_FILE_EXTENSION);
	std::string data_2 = file_handler_2.get_contents();
	Tokenizer tokenizer_2(data_2);

	data = file_handler_2.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events",					kTokenKindBlockName, 		1));
	expected.push_back(Token("{",							kTokenKindBraces, 			1));
	expected.push_back(Token("}", 						kTokenKindBraces, 			2));
	expected.push_back(Token("http",						kTokenKindBlockName, 		4));
	expected.push_back(Token("{", 						kTokenKindBraces, 			4));
	expected.push_back(Token("server", 					kTokenKindBlockName,		5));
	expected.push_back(Token("{", 						kTokenKindBraces, 			5));
	expected.push_back(Token("listen", 					kTokenKindDirectiveName,	6));
	expected.push_back(Token("80", 						kTokenKindDirectiveParam, 	6));
	expected.push_back(Token(";", 						kTokenKindSemicolin, 		6));
	expected.push_back(Token("server_name", 				kTokenKindDirectiveName, 	7));
	expected.push_back(Token("example.com", 				kTokenKindDirectiveParam,	7));
	expected.push_back(Token("www.example.com",			kTokenKindDirectiveParam,	7));
	expected.push_back(Token(";", 						kTokenKindSemicolin, 		7));
	expected.push_back(Token("root", 						kTokenKindDirectiveName, 	9));
	expected.push_back(Token("/var/www/html", 			kTokenKindDirectiveParam, 	9));
	expected.push_back(Token(";", 						kTokenKindSemicolin, 		9));
	expected.push_back(Token("}", 						kTokenKindBraces, 			10));
	expected.push_back(Token("location", 					kTokenKindBlockName, 		12));
	expected.push_back(Token("/some-directory/", 			kTokenKindBlockParam, 		12));
	expected.push_back(Token("{", 						kTokenKindBraces, 			12));
	expected.push_back(Token("autoindex",					kTokenKindDirectiveName, 	13));
	expected.push_back(Token("on", 						kTokenKindDirectiveParam, 	13));
	expected.push_back(Token(";", 						kTokenKindSemicolin, 		13));
	expected.push_back(Token("}", 						kTokenKindBraces, 			14));
	expected.push_back(Token("location", 					kTokenKindBlockName, 		16));
	expected.push_back(Token("/uploads", 					kTokenKindBlockParam, 		16));
	expected.push_back(Token("{", 						kTokenKindBraces, 			16));
	expected.push_back(Token("client_max_body_size", 		kTokenKindDirectiveName, 	17));
	expected.push_back(Token("20M", 						kTokenKindDirectiveParam, 	17));
	expected.push_back(Token(";",							kTokenKindSemicolin, 		17));
	expected.push_back(Token("root", 						kTokenKindDirectiveName, 	18));
	expected.push_back(Token("/path/to/upload/directory",	kTokenKindDirectiveParam, 	18));
	expected.push_back(Token(";", 						kTokenKindSemicolin, 		18));
	expected.push_back(Token("}", 						kTokenKindBraces, 			19));
	expected.push_back(Token("}", 						kTokenKindBraces, 			20));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);

	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());
}



TEST(TestTokenizer, TestTokenizerValidationNG) {
	std::string data;
	Tokenizer tokenizer;
	std::deque<Token> expected, actual;
	Result<int, std::string> result;

	const char *conf_path_1 = "test/test_conf/ng/token_ng1.conf";
	FileHandler file_handler_1(conf_path_1, CONFIG_FILE_EXTENSION);
	std::string data_1 = file_handler_1.get_contents();
	Tokenizer tokenizer_1(data_1);

	data = file_handler_1.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 		kTokenKindBraces, 		1));
	expected.push_back(Token("{", 		kTokenKindBraces,		1));
	expected.push_back(Token("}", 		kTokenKindBraces,		2));
	expected.push_back(Token("http", 		kTokenKindBlockName, 	4));
	expected.push_back(Token("{", 		kTokenKindBraces, 		4));
	expected.push_back(Token("}", 		kTokenKindBraces, 		5));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_2 = "test/test_conf/ng/token_ng2.conf";
	FileHandler file_handler_2(conf_path_2, CONFIG_FILE_EXTENSION);
	std::string data_2 = file_handler_2.get_contents();
	Tokenizer tokenizer_2(data_2);

	data = file_handler_2.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 		kTokenKindBraces, 		1));
	expected.push_back(Token("}", 		kTokenKindBraces, 		2));
	expected.push_back(Token("http", 		kTokenKindBlockName, 	4));
	expected.push_back(Token("{", 		kTokenKindBraces, 		4));
	expected.push_back(Token("}", 		kTokenKindBraces, 		5));
	expected.push_back(Token("}", 		kTokenKindBraces,		5));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_3 = "test/test_conf/ng/token_ng3.conf";
	FileHandler file_handler_3(conf_path_3, CONFIG_FILE_EXTENSION);
	std::string data_3 = file_handler_3.get_contents();
	Tokenizer tokenizer_3(data_3);

	data = file_handler_3.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 		kTokenKindBlockName, 		1));
	expected.push_back(Token("{", 			kTokenKindBraces, 			1));
	expected.push_back(Token("}", 			kTokenKindBraces, 			2));
	expected.push_back(Token("http", 			kTokenKindBlockName, 		4));
	expected.push_back(Token("{",				kTokenKindBraces, 			4));
	expected.push_back(Token("server", 		kTokenKindBlockName, 		5));
	expected.push_back(Token("{", 			kTokenKindBraces, 			5));
	expected.push_back(Token("listen", 		kTokenKindDirectiveName, 	6));
	expected.push_back(Token("80", 			kTokenKindDirectiveParam,	6));
	expected.push_back(Token(";",				kTokenKindSemicolin, 		6));
	expected.push_back(Token("{", 			kTokenKindBraces, 			6));
	expected.push_back(Token("server_name", 	kTokenKindDirectiveName, 	7));
	expected.push_back(Token(";", 			kTokenKindSemicolin, 		7));
	expected.push_back(Token("example.com", 	kTokenKindError,			7));  // after`;` and != block_name -> error
	expected.push_back(Token(";", 			kTokenKindSemicolin, 		7));
	expected.push_back(Token("}", 			kTokenKindBraces, 			8));
	expected.push_back(Token("location", 		kTokenKindBlockName, 		10));
	expected.push_back(Token("a",				kTokenKindBlockParam, 		10));
	expected.push_back(Token("b", 			kTokenKindBlockParam, 		10));
	expected.push_back(Token("c", 			kTokenKindBlockParam, 		10));
	expected.push_back(Token(";", 			kTokenKindSemicolin, 		10));
	expected.push_back(Token("{",				kTokenKindBraces, 			10));
	expected.push_back(Token(";", 			kTokenKindSemicolin, 		10));
	expected.push_back(Token("}", 			kTokenKindBraces, 			10));
	expected.push_back(Token("}", 			kTokenKindBraces, 			11));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_4 = "test/test_conf/ng/token_ng4.conf";
	FileHandler file_handler_4(conf_path_4, CONFIG_FILE_EXTENSION);
	std::string data_4 = file_handler_4.get_contents();
	Tokenizer tokenizer_4(data_4);

	data = file_handler_4.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 			kTokenKindBlockName, 		1));
	expected.push_back(Token("{", 				kTokenKindBraces, 			1));
	expected.push_back(Token("events", 			kTokenKindBlockName, 		2));
	expected.push_back(Token("{", 				kTokenKindBraces, 			2));
	expected.push_back(Token("}", 				kTokenKindBraces, 			2));
	expected.push_back(Token("}", 				kTokenKindBraces, 			3));
	expected.push_back(Token("http",	 			kTokenKindBlockName,		5));
	expected.push_back(Token("{", 				kTokenKindBraces, 			5));
	expected.push_back(Token("server", 			kTokenKindBlockName, 		6));
	expected.push_back(Token("{", 				kTokenKindBraces, 			6));
	expected.push_back(Token("listen", 			kTokenKindDirectiveName, 	7));
	expected.push_back(Token("80", 				kTokenKindDirectiveParam, 	7));
	expected.push_back(Token(";", 				kTokenKindSemicolin, 		7));
	expected.push_back(Token("{", 				kTokenKindBraces, 			7));
	expected.push_back(Token("server_name", 		kTokenKindDirectiveName, 	8));
	expected.push_back(Token("example.com", 		kTokenKindDirectiveParam, 	8));
	expected.push_back(Token("www.example.com",	kTokenKindDirectiveParam, 	8));
	expected.push_back(Token(";", 				kTokenKindSemicolin, 		8));
	expected.push_back(Token("root", 				kTokenKindDirectiveName, 	10));
	expected.push_back(Token("/var/www/html", 	kTokenKindDirectiveParam, 	10));
	expected.push_back(Token(";",	 				kTokenKindSemicolin, 		10));
	expected.push_back(Token("}", 				kTokenKindBraces, 			11));
	expected.push_back(Token("location", 			kTokenKindBlockName, 		13));
	expected.push_back(Token("/some-directory/", 	kTokenKindBlockParam, 		13));
	expected.push_back(Token("{", 				kTokenKindBraces, 			13));
	expected.push_back(Token("autoindex", 		kTokenKindDirectiveName, 	14));
	expected.push_back(Token("on",				kTokenKindDirectiveParam, 	14));
	expected.push_back(Token(";", 				kTokenKindSemicolin, 		14));
	expected.push_back(Token(";", 				kTokenKindSemicolin, 		14));
	expected.push_back(Token("{", 				kTokenKindBraces, 			14));
	expected.push_back(Token("aaa", 				kTokenKindError, 			14));  // error
	expected.push_back(Token("}", 				kTokenKindBraces, 			14));
	expected.push_back(Token("}", 				kTokenKindBraces, 			15));
	expected.push_back(Token("}", 				kTokenKindBraces, 			16));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_5 = "test/test_conf/ng/token_ng5.conf";
	FileHandler file_handler_5(conf_path_5, CONFIG_FILE_EXTENSION);
	std::string data_5 = file_handler_5.get_contents();
	Tokenizer tokenizer_5(data_5);

	data = file_handler_5.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 	kTokenKindBlockName,		1));
	expected.push_back(Token("{", 		kTokenKindBraces,			1));
	expected.push_back(Token("}", 		kTokenKindBraces,			2));
	expected.push_back(Token("http", 		kTokenKindBlockName,		4));
	expected.push_back(Token("{", 		kTokenKindBraces,			4));
	expected.push_back(Token("location", 	kTokenKindBlockName,		5));
	expected.push_back(Token("\"", 		kTokenKindError,			5));  // error
	expected.push_back(Token("{", 		kTokenKindBraces,			5));
	expected.push_back(Token("\"", 		kTokenKindError,			5));
	expected.push_back(Token("{", 		kTokenKindBraces,			5));
	expected.push_back(Token("a", 		kTokenKindError,			6));  // error
	expected.push_back(Token(";", 		kTokenKindSemicolin,		6));
	expected.push_back(Token("b", 		kTokenKindError,			7));  // error
	expected.push_back(Token("c", 		kTokenKindError,			7));  // error
	expected.push_back(Token(";", 		kTokenKindSemicolin,		7));
	expected.push_back(Token("}", 		kTokenKindBraces,			8));
	expected.push_back(Token("}", 		kTokenKindBraces,			9));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_6 = "test/test_conf/ng/token_ng6.conf";
	FileHandler file_handler_6(conf_path_6, CONFIG_FILE_EXTENSION);
	std::string data_6 = file_handler_6.get_contents();
	Tokenizer tokenizer_6(data_6);

	data = file_handler_6.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("events", 		kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 			kTokenKindBraces, 		1));
	expected.push_back(Token("}", 			kTokenKindBraces, 		2));
	expected.push_back(Token("http", 			kTokenKindBlockName, 	4));
	expected.push_back(Token("{", 			kTokenKindBraces, 		4));
	expected.push_back(Token("location", 		kTokenKindBlockName, 	5));
	expected.push_back(Token("\\", 			kTokenKindError, 		5));  // error
	expected.push_back(Token("{", 			kTokenKindBraces, 		5));
	expected.push_back(Token("}", 			kTokenKindBraces, 		5));
	expected.push_back(Token("}", 			kTokenKindBraces, 		6));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);
}


TEST(TestTokenizer, TestSimpleNG) {
	std::string data;
	Tokenizer tokenizer;
	std::deque<Token> expected, actual;
	Result<int, std::string> result;

	const char *conf_path_1 = "test/test_conf/ng/ng01.conf";
	FileHandler file_handler_1(conf_path_1, CONFIG_FILE_EXTENSION);
	std::string data_1 = file_handler_1.get_contents();
	Tokenizer tokenizer_1(data_1);

	data = file_handler_1.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("a", 	kTokenKindError, 	1));  // error

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_2 = "test/test_conf/ng/ng02.conf";
	FileHandler file_handler_2(conf_path_2, CONFIG_FILE_EXTENSION);
	std::string data_2 = file_handler_2.get_contents();
	Tokenizer tokenizer_2(data_2);

	data = file_handler_2.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("{", 	kTokenKindBraces, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_3 = "test/test_conf/ng/ng03.conf";
	FileHandler file_handler_3(conf_path_3, CONFIG_FILE_EXTENSION);
	std::string data_3 = file_handler_3.get_contents();
	Tokenizer tokenizer_3(data_3);

	data = file_handler_3.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("}", 	kTokenKindBraces, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_4 = "test/test_conf/ng/ng04.conf";
	FileHandler file_handler_4(conf_path_4, CONFIG_FILE_EXTENSION);
	std::string data_4 = file_handler_4.get_contents();
	Tokenizer tokenizer_4(data_4);

	data = file_handler_4.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("{", 	kTokenKindBraces, 	1));
	expected.push_back(Token("}", 	kTokenKindBraces, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_5 = "test/test_conf/ng/ng05.conf";
	FileHandler file_handler_5(conf_path_5, CONFIG_FILE_EXTENSION);
	std::string data_5 = file_handler_5.get_contents();
	Tokenizer tokenizer_5(data_5);

	data = file_handler_5.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("{", 	kTokenKindBraces, 		1));
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_6 = "test/test_conf/ng/ng06.conf";
	FileHandler file_handler_6(conf_path_6, CONFIG_FILE_EXTENSION);
	std::string data_6 = file_handler_6.get_contents();
	Tokenizer tokenizer_6(data_6);

	data = file_handler_6.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_7 = "test/test_conf/ng/ng07.conf";
	FileHandler file_handler_7(conf_path_7, CONFIG_FILE_EXTENSION);
	std::string data_7 = file_handler_7.get_contents();
	Tokenizer tokenizer_7(data_7);

	data = file_handler_7.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("}", 	kTokenKindBraces, 		1));
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_8 = "test/test_conf/ng/ng08.conf";
	FileHandler file_handler_8(conf_path_8, CONFIG_FILE_EXTENSION);
	std::string data_8 = file_handler_8.get_contents();
	Tokenizer tokenizer_8(data_8);

	data = file_handler_8.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("location", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 		kTokenKindBraces, 		1));
	expected.push_back(Token("location", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("}", 		kTokenKindBraces, 		1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_9 = "test/test_conf/ng/ng09.conf";
	FileHandler file_handler_9(conf_path_9, CONFIG_FILE_EXTENSION);
	std::string data_9 = file_handler_9.get_contents();
	Tokenizer tokenizer_9(data_9);

	data = file_handler_9.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	1));
	expected.push_back(Token("{", 	kTokenKindBraces, 		3));
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	4));
	expected.push_back(Token("}", 	kTokenKindBraces, 		6));
	expected.push_back(Token("http", 	kTokenKindBlockName, 	9));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_10 = "test/test_conf/ng/ng10.conf";
	FileHandler file_handler_10(conf_path_10, CONFIG_FILE_EXTENSION);
	std::string data_10 = file_handler_10.get_contents();
	Tokenizer tokenizer_10(data_10);

	data = file_handler_10.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("http", 	kTokenKindBlockName, 	1));  // http{ -> separate: http {
	expected.push_back(Token("{", 	kTokenKindBraces, 		1));
	expected.push_back(Token("}", 	kTokenKindBraces, 		1));
	expected.push_back(Token("\\n", 	kTokenKindError, 		3));  // error

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_11 = "test/test_conf/ng/empty.conf";
	FileHandler file_handler_11(conf_path_11, CONFIG_FILE_EXTENSION);
	std::string data_11 = file_handler_11.get_contents();
	Tokenizer tokenizer_11(data_11);

	data = file_handler_11.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());
}


TEST(TestTokenizer, TestComment) {
	std::string data;
	Tokenizer tokenizer;
	std::deque<Token> expected, actual;
	Result<int, std::string> result;

	const char *conf_path_1 = "test/test_conf/comment/comment01.conf";
	FileHandler file_handler_1(conf_path_1, CONFIG_FILE_EXTENSION);
	std::string data_1 = file_handler_1.get_contents();
	Tokenizer tokenizer_1(data_1);

	data = file_handler_1.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("#", 	kTokenKindComment, 	1));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_2 = "test/test_conf/comment/comment02.conf";
	FileHandler file_handler_2(conf_path_2, CONFIG_FILE_EXTENSION);
	std::string data_2 = file_handler_2.get_contents();
	Tokenizer tokenizer_2(data_2);

	data = file_handler_2.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	2));
	expected.push_back(Token(";", 	kTokenKindSemicolin, 	3));
	expected.push_back(Token("#", 	kTokenKindComment, 	4));
	expected.push_back(Token("http", 	kTokenKindComment, 	4));
	expected.push_back(Token("{", 	kTokenKindComment, 	4));
	expected.push_back(Token("}", 	kTokenKindComment, 	4));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_3 = "test/test_conf/comment/comment03.conf";
	FileHandler file_handler_3(conf_path_3, CONFIG_FILE_EXTENSION);
	std::string data_3 = file_handler_3.get_contents();
	Tokenizer tokenizer_3(data_3);

	data = file_handler_3.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("http", 	kTokenKindBlockName, 	1));
	expected.push_back(Token("{", 	kTokenKindBraces, 		1));
	expected.push_back(Token("}", 	kTokenKindBraces, 		1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("this", 	kTokenKindComment, 	1));
	expected.push_back(Token("is", 	kTokenKindComment, 	1));
	expected.push_back(Token("comment",kTokenKindComment,	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	2));
	expected.push_back(Token("}", 	kTokenKindComment, 	2));
	expected.push_back(Token("a", 	kTokenKindError, 		5));  // error
	expected.push_back(Token("#", 	kTokenKindComment, 	5));
	expected.push_back(Token("b", 	kTokenKindComment, 	5));
	expected.push_back(Token("#", 	kTokenKindComment, 	5));
	expected.push_back(Token("c", 	kTokenKindComment, 	5));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_err());
	print_error_msg(result, __LINE__);

	////////////////////////////////////////////////////////////////////////////

	const char *conf_path_4 = "test/test_conf/comment/comment04.conf";
	FileHandler file_handler_4(conf_path_4, CONFIG_FILE_EXTENSION);
	std::string data_4 = file_handler_4.get_contents();
	Tokenizer tokenizer_4(data_4);

	data = file_handler_4.get_contents();
	tokenizer = Tokenizer(data);

	expected = {};
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	1));
	expected.push_back(Token("#", 	kTokenKindComment, 	2));
	expected.push_back(Token("http", 	kTokenKindBlockName, 	5));
	expected.push_back(Token("#", 	kTokenKindComment, 	5));
	expected.push_back(Token("{", 	kTokenKindComment, 	5));
	expected.push_back(Token("}", 	kTokenKindComment, 	5));
	expected.push_back(Token("{", 	kTokenKindBraces, 		6));
	expected.push_back(Token("#", 	kTokenKindComment, 	7));
	expected.push_back(Token(";", 	kTokenKindComment, 	7));
	expected.push_back(Token("}", 	kTokenKindBraces, 		8));
	expected.push_back(Token("#", 	kTokenKindComment, 	8));
	expected.push_back(Token("{", 	kTokenKindComment, 	8));

	actual = tokenizer.get_tokens();
	result = tokenizer.get_result();

	expect_eq_tokens(expected, actual, __LINE__);
	print_tokens(tokenizer);

	EXPECT_TRUE(result.is_ok());

}
