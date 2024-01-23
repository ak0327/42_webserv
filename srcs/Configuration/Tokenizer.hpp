#pragma once

# include <string>

enum e_token_kind {
	kWord,
	kBraces,
	kBlockName,
	kDirectiveName,
	kDirectiveParam,
	kSemicolin
};

struct Token {
	std::string word;
	e_token_kind kind;
};

class Tokenizer {
};
