#pragma once

# include <deque>
# include <string>
# include "Result.hpp"
# include "Token.hpp"

class Tokenizer {
 public:
	Tokenizer();
	explicit Tokenizer(const std::string &data);
	Tokenizer(const Tokenizer &others);
	~Tokenizer();
	Tokenizer &operator=(const Tokenizer &rhs);

	std::deque<Token> get_tokens();
	Result<int, std::string> get_result();

	static std::deque<std::string> split_by_delimiter(const std::string &data,
													  char delimiter,
													  bool is_keeping_delimiter);
	static std::deque<std::string> split_by_delimiter(const std::deque<std::string> &data,
													  char delimiter,
													  bool is_keeping_delimiter);
	static std::deque<std::string> split_data(const std::string &data);

	static std::deque<Token> create_tokens(const std::deque<std::string> &split);
	static Result<int, std::string> validate_tokens(std::deque<Token> *tokens);

 private:
	std::deque<Token> tokens_;
	Result<int, std::string> result_;

	static std::deque<Token> init_tokens(const std::deque<std::string> &split);
	static void remove_token(std::deque<Token> *tokens, TokenKind remove_kind);

	static void tagging_line_feed(std::deque<Token> *tokens);
	static void tagging_comment(std::deque<Token> *tokens);
	static void tagging_delimiter(std::deque<Token> *tokens);

	static void tagging_block(std::deque<Token> *tokens);
	static void tagging_block_name(std::deque<Token> *tokens);
	static void tagging_block_param(std::deque<Token> *tokens);

	static void tagging_directive(std::deque<Token> *tokens);
	static void tagging_directive_name(std::deque<Token> *tokens);
	static void tagging_directive_param(std::deque<Token> *tokens);

	static void tagging_token(std::deque<Token> *tokens,
                              bool (*is_tagging_token)(const std::string &),
                              TokenKind tagging_kind);
	static void tagging_tokens(std::deque<Token> *tokens,
                               bool (*is_range_start)(TokenKind),
                               bool (*is_range_end)(TokenKind),
                               TokenKind tagging_kind);
};

std::ostream &operator<<(std::ostream &out, Tokenizer &tokenizer);
