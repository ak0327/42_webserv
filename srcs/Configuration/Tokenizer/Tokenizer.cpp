#include <algorithm>
#include <iostream>
#include <sstream>
#include <vector>
#include "Constant.hpp"
#include "Color.hpp"
#include "Token.hpp"
#include "Tokenizer.hpp"

namespace {


bool is_token_kind_braces(const std::string &token_str) {
	return (token_str == "{" || token_str == "}");
}


bool is_token_kind_braces(TokenKind kind) {
	return kind == kTokenKindBraces;
}


bool is_token_kind_block_name(const std::string &token_str) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(BLOCK_NAMES.begin(), BLOCK_NAMES.end(), token_str);
	return itr != BLOCK_NAMES.end();
}


bool is_token_kind_block_name(TokenKind kind) {
	return kind == kTokenKindBlockName;
}


bool is_token_kind_directive_name(const std::string &token_str) {
	std::vector<std::string>::const_iterator itr;

	itr = std::find(DIRECTIVE_NAMES.begin(), DIRECTIVE_NAMES.end(), token_str);
	return itr != DIRECTIVE_NAMES.end();
}


bool is_token_kind_directive_name(TokenKind kind) {
	return kind == kTokenKindDirectiveName;
}


bool is_token_kind_semicolon(const std::string &token_str) {
	return token_str == ";";
}


bool is_token_kind_semicolon(TokenKind kind) {
	return kind == kTokenKindSemicolin;
}


bool is_token_kind_parameter(TokenKind kind) {
	return (kind == kTokenKindBlockParam || kind == kTokenKindDirectiveParam);
}


bool is_token_kind_init(TokenKind kind) {
	return kind == kTokenKindInit;
}


bool is_token_kind_line_feed(const std::string &token_str) {
	return token_str == std::string(1, LF);
}


bool is_token_kind_line_feed(TokenKind kind) {
	return kind == kTokenKindLineFeed;
}


bool is_token_kind_comment(const std::string &token_str) {
	return token_str == std::string(1, COMMENT_SYMBOL);
}


bool is_token_kind_comment(TokenKind kind) {
	return kind == kTokenKindComment;
}


}  // namespace

////////////////////////////////////////////////////////////////////////////////

Tokenizer::Tokenizer() : tokens_() {}


Tokenizer::Tokenizer(const std::string &data) {
	std::deque<std::string> split;
	std::deque<Token> tagging_result;
	std::string error_msg;

	split = split_data(data);
	this->tokens_ = create_tokens(split);
	this->result_ = validate_tokens(&this->tokens_);
}


Tokenizer::Tokenizer(const Tokenizer &others) {
	*this = others;
}


Tokenizer::~Tokenizer() {}


Tokenizer &Tokenizer::operator=(const Tokenizer &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->tokens_ = rhs.tokens_;
	this->result_ = rhs.result_;
	return *this;
}


std::deque<std::string> Tokenizer::split_data(const std::string &data) {
	std::deque<std::string> split_by_space;
	std::deque<std::string> split_by_line_feed;
	std::deque<std::string> split_by_left_brace, split_by_right_brace;
	std::deque<std::string> split_by_semicolon;
	std::deque<std::string> split_by_hash;

	split_by_space = split_by_delimiter(data, SP, false);
	split_by_line_feed = split_by_delimiter(split_by_space, LF, true);
	split_by_left_brace = split_by_delimiter(split_by_line_feed, LBRACES, true);
	split_by_right_brace = split_by_delimiter(split_by_left_brace, RBRACES, true);
	split_by_semicolon = split_by_delimiter(split_by_right_brace, SEMICOLON, true);
	split_by_hash = split_by_delimiter(split_by_semicolon, COMMENT_SYMBOL, true);

	return split_by_hash;
}


std::deque<std::string> Tokenizer::split_by_delimiter(const std::string &data,
													  char delimiter,
													  bool is_keeping_delimiter) {
	std::deque<std::string> split;
	std::string token;
	char c;

	for (std::size_t pos = 0; pos < data.length(); ++pos) {
		c = data[pos];
		if (c != delimiter) {
			token += c;
		} else {
			if (!token.empty()) {
				split.push_back(token);
				token.clear();
			}
			if (is_keeping_delimiter) {
				split.push_back(std::string(1, c));
			}
		}
	}

	if (!token.empty()) {
		split.push_back(token);
	}

	return split;
}


std::deque<std::string> Tokenizer::split_by_delimiter(const std::deque<std::string> &data,
													  char delimiter,
													  bool is_keeping_delimiter) {
	std::deque<std::string> split, split_elem;
	std::deque<std::string>::const_iterator itr;

	for (itr = data.begin(); itr != data.end(); ++itr) {
		split_elem = split_by_delimiter(*itr, delimiter, is_keeping_delimiter);
		split.insert(split.end(), split_elem.begin(), split_elem.end());
	}

	return split;
}


std::deque<Token> Tokenizer::init_tokens(const std::deque<std::string> &split) {
	std::deque<Token> tokens;
	std::deque<std::string>::const_iterator itr;
	std::string token_str;
	std::size_t line_number;

	line_number = 1;
	for (itr = split.begin(); itr != split.end(); ++itr) {
		token_str = *itr;
		if (token_str == std::string(1, LF)) {
			++line_number;
			// continue;
		}

		tokens.push_back(Token(token_str, kTokenKindInit, line_number));
	}
	return tokens;
}


void Tokenizer::remove_token(std::deque<Token> *tokens, TokenKind remove_kind) {
	std::deque<Token>::iterator token;

	if (!tokens) { return; }

	for (token = tokens->begin(); token != tokens->end();) {
		if ((*token).kind_ == remove_kind) {
			token = tokens->erase(token);
		} else {
			++token;
		}
	}
}


void Tokenizer::tagging_delimiter(std::deque<Token> *tokens) {
	std::deque<Token>::iterator token;

	if (!tokens) { return; }

	for (token = tokens->begin(); token != tokens->end(); ++token) {
		if (!is_token_kind_init((*token).kind_)) {
			continue;
		}

		if (is_token_kind_braces((*token).str_)) {
			(*token).kind_ = kTokenKindBraces;
		} else if (is_token_kind_semicolon((*token).str_)) {
			(*token).kind_ = kTokenKindSemicolin;
		}
	}
}


void Tokenizer::tagging_line_feed(std::deque<Token> *tokens) {
	tagging_token(tokens,
				 is_token_kind_line_feed,
				 kTokenKindLineFeed);
}


void Tokenizer::tagging_token(std::deque<Token> *tokens,
                              bool (*is_tagging_token)(const std::string &),
                              TokenKind tagging_kind) {
	std::deque<Token>::iterator token;

	if (!tokens) { return; }

	for (token = tokens->begin(); token != tokens->end(); ++token) {
		if (!is_token_kind_init(token->kind_)) {
			continue;
		}
		if (is_tagging_token((*token).str_)) {
			(*token).kind_ = tagging_kind;
		}
	}
}


/*
 block_name  param  param ...  {
 ^^^^^^^^^^  ^^^^^  ^^^^^ ^^^  ^
 BlockName   BlockParam       reset
 */
void Tokenizer::tagging_block(std::deque<Token> *tokens) {
	tagging_block_name(tokens);
	tagging_block_param(tokens);
}


void Tokenizer::tagging_block_name(std::deque<Token> *tokens) {
	tagging_token(tokens,
				  is_token_kind_block_name,
				  kTokenKindBlockName);
}

void Tokenizer::tagging_block_param(std::deque<Token> *tokens) {
	tagging_tokens(tokens,
				   is_token_kind_block_name,
				   is_token_kind_braces,
				   kTokenKindBlockParam);
}



/*
 directive_name  param  param ...  ;
 ^^^^^^^^^^^^^^  ^^^^^  ^^^^^ ^^^  ^
 DirectiveName   DirectiveParam   reset
 */
void Tokenizer::tagging_directive(std::deque<Token> *tokens) {
	tagging_directive_name(tokens);
	tagging_directive_param(tokens);
}

void Tokenizer::tagging_directive_name(std::deque<Token> *tokens) {
	tagging_token(tokens,
				  is_token_kind_directive_name,
				  kTokenKindDirectiveName);
}


void Tokenizer::tagging_directive_param(std::deque<Token> *tokens) {
	tagging_tokens(tokens,
				   is_token_kind_directive_name,
				   is_token_kind_semicolon,
				   kTokenKindDirectiveParam);
}


/*
     # comment comment ...  \n
start^ ^^^^^^^ ^^^^^^^ ^^^  ^^end
 */
void Tokenizer::tagging_comment(std::deque<Token> *tokens) {
	tagging_token(tokens,
				  is_token_kind_comment,
				  kTokenKindComment);
	tagging_tokens(tokens,
				   is_token_kind_comment,
				   is_token_kind_line_feed,
				   kTokenKindComment);
}


void Tokenizer::tagging_tokens(std::deque<Token> *tokens,
                               bool (*is_range_start)(TokenKind),
                               bool (*is_range_end)(TokenKind),
                               TokenKind tagging_kind) {
	std::deque<Token>::iterator token;
	bool is_param;

	if (!tokens) { return; }

	is_param = false;
	for (token = tokens->begin(); token != tokens->end(); ++token) {
		if (is_range_start(token->kind_)) {
			is_param = true;
			continue;
		} else if (is_range_end(token->kind_)) {
			is_param = false;
		}
		if (!is_param) {
			continue;
		}

		if (is_token_kind_init(token->kind_)) {
			token->kind_ = tagging_kind;
		}
	}
}


std::deque<Token> Tokenizer::create_tokens(const std::deque<std::string> &split) {
	std::deque<Token> tokens;

	tokens = init_tokens(split);

	tagging_line_feed(&tokens);
	tagging_comment(&tokens);
	remove_token(&tokens, kTokenKindLineFeed);

	tagging_delimiter(&tokens);
	tagging_block(&tokens);
	tagging_directive(&tokens);
	return tokens;
}


bool is_valid_character_for_token_param(const std::string &param_str) {
	char c;
	const std::string invalid_char_for_param = "'\"\\";

	for (std::size_t pos = 0; pos < param_str.length(); ++pos) {
		c = param_str[pos];

		if (std::isprint(c)
		&& invalid_char_for_param.find(c) == std::string::npos) {
			continue;
		}
		return false;
	}
	return true;
}


Result<int, std::string> Tokenizer::validate_tokens(std::deque<Token> *tokens) {
	Result<int, std::string> validate_result;
	std::deque<Token>::iterator token;
	std::ostringstream error_msg;

	validate_result = Result<int, std::string>::ok(OK);

	for (token = tokens->begin(); token != tokens->end(); ++token) {
		if (is_token_kind_init(token->kind_)) {
			token->kind_ = kTokenKindError;
		} else if (is_token_kind_parameter(token->kind_)) {
			if (is_valid_character_for_token_param(token->str_)) {
				continue;
			}
			token->kind_ = kTokenKindError;
		} else {
			continue;
		}

		if (validate_result.is_ok()) {
			error_msg << "[Error] invalid token \"" << token->str_ << "\" in L" << token->line_number_;
			validate_result = Result<int, std::string>::err(error_msg.str());
		}
	}

	return validate_result;
}


std::deque<Token> Tokenizer::get_tokens() { return this->tokens_; }


Result<int, std::string> Tokenizer::get_result() { return this->result_; }


std::ostream &operator<<(std::ostream &out, Tokenizer &tokenizer) {
	const std::deque<Token> tokens = tokenizer.get_tokens();
	std::deque<Token>::const_iterator token;
	std::string word, kind, line;

	for (token = tokens.begin(); token != tokens.end(); ++token) {
		out << *token << std::endl;
	}
	return out;
}
