#pragma once

enum e_node_kind {
	kBlockHttp,
	kBlockServer,
	kBlockLocation,
	kBlockEvents,
	kDirectiveListen,
	kDirectiveServerName,
	kDirectiveErrorPage,
	kDirectiveReweite,
	kDirectiveReturn,
	kDirectiveAutoindex,
	kDirectiveClientMaxBodySize,
	kDirectiveRoot,
	kDirectiveIndex,
	kDirectiveCgi,
	kDirectiveCgiPath,
	kDirectiveCgiParam
};

class AbstractSyntaxTree {
};
