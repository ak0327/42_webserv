#include "Constant.hpp"
#include "Token.hpp"

Token::Token()
	: str_(std::string(EMPTY)),
	  kind_(kTokenKindInit),
	  line_number_() {}


Token::Token(const std::string &str,
			 e_token_kind kind,
			 std::size_t line_number)
	: str_(str),
	  kind_(kind),
	  line_number_(line_number) {}


Token::Token(const Token &other) {
	*this = other;
}


Token::~Token() {}


Token &Token::operator=(const Token &rhs) {
	if (this == &rhs) {
		return *this;
	}
	this->str_ = rhs.str_;
	this->kind_ = rhs.kind_;
	this->line_number_ = rhs.line_number_;
	return *this;
}


std::string Token::get_token_kind_str(e_token_kind kind) {
	switch (kind) {
		case kTokenKindInit:
			return "Init";
		case kTokenKindBraces:
			return "Braces";
		case kTokenKindBlockName:
			return "BlockName";
		case kTokenKindBlockParam:
			return "BlockParam";
		case kTokenKindDirectiveName:
			return "DirectiveName";
		case kTokenKindDirectiveParam:
			return "DirectiveParam";
		case kTokenKindSemicolin:
			return "Semicolon";
		case kTokenKindComment:
			return "Comment";
		case kTokenKindLineFeed:
			return "LineFeed";
		case kTokenKindError:
			return "Error";

		default:
			return RED "*** FatalError ***" RESET;
	}
}


std::string Token::get_token_output(const Token &token, bool with_color) {
	std::stringstream ss, word_ss, kind_ss, line_ss;
	int word_width = 25;
	int kind_width = 15;

	if (with_color) {
		word_width += static_cast<int>(std::string(GRAY CYAN GRAY RESET).length());
		kind_width += static_cast<int>(std::string(GRAY CYAN RESET).length());
		word_ss << GRAY << "token:[" << CYAN << token.str_ << GRAY << "]" << RESET;
		kind_ss << GRAY << "kind:" << CYAN << Token::get_token_kind_str(token.kind_) << RESET;
		line_ss << GRAY << "L:" << CYAN << token.line_number_ << RESET;
	} else {
		word_ss << "token:[" << token.str_ << "]";
		kind_ss << "kind:" << Token::get_token_kind_str(token.kind_);
		line_ss << "L:" << token.line_number_;
	}

	ss << std::left << std::setw(word_width) << word_ss.str();
	ss << " ";
	ss << std::left << std::setw(kind_width) << kind_ss.str();
	ss << " ";
	ss << std::left << line_ss.str();

	return ss.str();
}

std::ostream &operator<<(std::ostream &out, const Token &token) {
	std::stringstream ss;

	out << Token::get_token_output(token, true);
	return out;
}
