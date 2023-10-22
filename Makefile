NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP
CXXFLAGS	+=	-g -fsanitize=address,undefined -fno-omit-frame-pointer

# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

#main
SRCS		=	main.cpp \
				get_valid_config_file_path.cpp

#const
CONST_DIR	=	Const
SRCS		+=	$(CONST_DIR)/Constant.cpp

#error
ERROR_DIR	=	Error
SRCS		+=	$(ERROR_DIR)/Error.cpp

#debug
DEBUG_DIR	=	Debug
SRCS		+=	$(DEBUG_DIR)/Debug.cpp

#socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp

#StringHandler
STR_HANDLER	=	StringHandler
SRCS		+=	$(STR_HANDLER)/HttpMessageParser.cpp \
				$(STR_HANDLER)/HttpMessageParserIs.cpp \
				$(STR_HANDLER)/HttpMessageParserSkip.cpp \
				$(STR_HANDLER)/StringHandler.cpp

#httprequest
REQUEST_DIR	=	HttpRequest
SRCS		+=	$(REQUEST_DIR)/HttpRequest.cpp \
				$(REQUEST_DIR)/RequestLine/RequestLine.cpp \
				$(REQUEST_DIR)/HttpRequest_TwoValueSet.cpp \
				$(REQUEST_DIR)/HttpRequest_ValueWeightArraySet.cpp

SRCS		+= 	$(REQUEST_DIR)/FieldValueBase/FieldValueBase.cpp \
				$(REQUEST_DIR)/LinkClass/LinkClass.cpp \
				$(REQUEST_DIR)/RequestLine/RequestLine.cpp \
				$(REQUEST_DIR)/SingleFieldValue/SingleFieldValue.cpp \
				$(REQUEST_DIR)/TwoValueSet/TwoValueSet.cpp \
				$(REQUEST_DIR)/ValueWeightArraySet/ValueWeightArraySet.cpp \
				$(REQUEST_DIR)/ValueAndMapFieldValues/ValueAndMapFieldValues.cpp \
				$(REQUEST_DIR)/ValueAndMapFieldValues/set_content_disposition.cpp \

DATE_DIR	= 	$(REQUEST_DIR)/Date
SRCS		+=	$(DATE_DIR)/Date.cpp \
				$(DATE_DIR)/set_date.cpp

MAP_FIELD_VALUES_DIR = $(REQUEST_DIR)/MapFieldValues
SRCS		+=	$(MAP_FIELD_VALUES_DIR)/MapFieldValues.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_authorization.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_cache_control.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_cookie.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_forwarded.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_host.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_keep_alive.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_range.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_upgrade.cpp

MAP_SET_FIELD_VALUES_DIR = $(REQUEST_DIR)/MapSetFieldValues
SRCS		+=	$(MAP_SET_FIELD_VALUES_DIR)/MapSetFieldValues.cpp \
				$(MAP_SET_FIELD_VALUES_DIR)/set_link.cpp \
				$(MAP_SET_FIELD_VALUES_DIR)/set_via.cpp

MEDIA_TYPE_DIR = $(REQUEST_DIR)/MediaType
SRCS		+=	$(MEDIA_TYPE_DIR)/MediaType.cpp \
				$(MEDIA_TYPE_DIR)/set_media_type.cpp

MULTI_FIELD_VALUES_DIR = $(REQUEST_DIR)/MultiFieldValues
SRCS		+=	$(MULTI_FIELD_VALUES_DIR)/MultiFieldValues.cpp \
				$(MULTI_FIELD_VALUES_DIR)/set_multi_field_values.cpp

SINGLE_FIELD_VALUE_DIR = $(REQUEST_DIR)/SingleFieldValue
SRCS		+=	$(SINGLE_FIELD_VALUE_DIR)/SingleFieldValue.cpp \
				$(SINGLE_FIELD_VALUE_DIR)/set_single_field_value.cpp


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes \
				$(SRCS_DIR)/$(CONST_DIR) \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR) \
				$(SRCS_DIR)/$(STR_HANDLER) \
				$(SRCS_DIR)/$(REQUEST_DIR) \
				$(SRCS_DIR)/$(DATE_DIR) \
				$(SRCS_DIR)/$(MAP_FIELD_VALUES_DIR) \
				$(SRCS_DIR)/$(MAP_SET_FIELD_VALUES_DIR) \
				$(SRCS_DIR)/$(MEDIA_TYPE_DIR) \
				$(SRCS_DIR)/$(MULTI_FIELD_VALUES_DIR) \
				$(SRCS_DIR)/$(SINGLE_FIELD_VALUE_DIR) \
				$(SRCS_DIR)/$(REQUEST_DIR)/FieldValueBase \
				$(SRCS_DIR)/$(REQUEST_DIR)/LinkClass \
				$(SRCS_DIR)/$(REQUEST_DIR)/RequestLine \
				$(SRCS_DIR)/$(REQUEST_DIR)/TwoValueSet \
				$(SRCS_DIR)/$(REQUEST_DIR)/ValueWeightArraySet

INCLUDES	 =	$(addprefix -I, $(INCLUDES_DIR))


# RULES ------------------------------------------------------------------------
.PHONY	: all
all		: $(NAME)

$(NAME)	: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJS_DIR)/%.o	: $(SRCS_DIR)/%.cpp
	@mkdir -p $$(dirname $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

.PHONY	: clean
clean	:
	rm -rf $(OBJS_DIR)

.PHONY	: fclean
fclean	: clean
	rm -f $(NAME)

.PHONY	: re
re		: fclean all

.PHONY	: lint
lint	:
	python3 -m cpplint --recursive srcs

.PHONY	: request_test
request_test: 

.PHONY	: run_unit_test
run_unit_test	:
	#rm -rf build
	cmake -S . -B build
	#cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT_MULTIPLEXER"
	cmake --build build
	#./build/unit_test 2>/dev/null
	./build/unit_test

.PHONY	: run_result_test
run_result_test	:
	#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Result*

.PHONY	: run_err_test
run_err_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=ErrorMessage*

.PHONY	: run_socket_test
run_socket_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=SocketUnitTest.*:SocketIntegrationTest.*

.PHONY    : run_request_test
run_request_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Request*

.PHONY    : run_handlingstring_test
run_handlingstring_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=HandlingString*

.PHONY    : run_httprequest_list_test
run_httprequest_list_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=List*

.PHONY    : run_httprequest_twoValueMap_test
run_httprequest_twoValueMap_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TwoValuseSet*

.PHONY    : run_httprequest_array_test
run_httprequest_array_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Array*

################################################################################

.PHONY    : run_string_test
run_string_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestStringHandler*:TestHttpMessageParser*

.PHONY    : run_rl_test
run_rl_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestRequestLine*

.PHONY    : run_http_request_test
run_http_request_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestHttpRequest*


.PHONY    : run_single_field_value_test
run_single_field_value_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestSingleFieldValue*


.PHONY    : run_multi_field_values_test
run_multi_field_values_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMultiFieldValues*


.PHONY    : run_map_field_values_test
run_map_field_values_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMapFieldValues*


.PHONY    : run_map_set_field_values_test
run_map_set_field_values_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMapSetFieldValues*


.PHONY    : run_value_and_map_test
run_value_and_map_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestValueAndMapFieldValues*


.PHONY    : run_media_test
run_media_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMediaType*


.PHONY    : run_date_test
run_date_test    :
#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestDate*

-include $(DEPS)
