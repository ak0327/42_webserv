#ifndef SRCS_HTTPREQUEST_BASEKEYVALUEMAP_BASEKEYVALUEMAP_HPP_
#define SRCS_HTTPREQUEST_BASEKEYVALUEMAP_BASEKEYVALUEMAP_HPP_

# include <map>
# include <string>

class	BaseKeyValueMap
{
	public:
		BaseKeyValueMap(void);
		BaseKeyValueMap(const BaseKeyValueMap &other);
		virtual ~BaseKeyValueMap();
};

#endif  // SRCS_HTTPREQUEST_BASEKEYVALUEMAP_BASEKEYVALUEMAP_HPP_
