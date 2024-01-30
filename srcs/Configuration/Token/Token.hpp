#pragma once

enum e_token_kind {
	kBraces,
	kBlockName,
	kBlockParam,
	kDirectiveName,
	kDirectiveParam,
	kSemicolin,
	kError
};

enum e_param_type {
	kInit,
	kBlock,
	kDirective
};

struct Token {
};
