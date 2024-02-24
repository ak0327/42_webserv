NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP -pedantic
CXXFLAGS	+=	-g -fsanitize=address,undefined -fno-omit-frame-pointer
CXXFLAGS	+=	-D USE_SELECT
CXXFLAGS	+=	-D DEBUG
#CXXFLAGS	+=	-D ECHO
#CXXFLAGS	+=	-D LEAKS

# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

# main
SRCS		=	main.cpp

# Config
CONFIG_DIR	=	Config
SRCS		+=	$(CONFIG_DIR)/FileHandler/FileHandler.cpp \
				$(CONFIG_DIR)/ConfigParser/ConfigParser.cpp \
				$(CONFIG_DIR)/Token/Token.cpp \
				$(CONFIG_DIR)/Tokenizer/Tokenizer.cpp \
				$(CONFIG_DIR)/Config.cpp

# Const
CONST_DIR	=	Const
SRCS		+=	$(CONST_DIR)/Constant.cpp

# ClientSession
CLIENT_SESSION_DIR = ClientSession
SRCS		+=	$(CLIENT_SESSION_DIR)/ClientSession.cpp

# Error
ERROR_DIR	=	Error
SRCS		+=	$(ERROR_DIR)/Error.cpp

# Debug
DEBUG_DIR	=	Debug
SRCS		+=	$(DEBUG_DIR)/Debug.cpp

# HTTP Request
REQUEST_DIR	=	HttpRequest
SRCS		+=	$(REQUEST_DIR)/HttpRequest.cpp \
				$(REQUEST_DIR)/RequestLine/RequestLine.cpp

SRCS		+= 	$(REQUEST_DIR)/FieldValueBase/FieldValueBase.cpp \
				$(REQUEST_DIR)/RequestLine/RequestLine.cpp \
				$(REQUEST_DIR)/SingleFieldValue/SingleFieldValue.cpp

DATE_DIR	= 	$(REQUEST_DIR)/Date
SRCS		+=	$(DATE_DIR)/Date.cpp \
				$(DATE_DIR)/set_date.cpp

FIELD_VALUE_WITH_WEIGHT = $(REQUEST_DIR)/FieldValueWithWeight
SRCS		+=	$(FIELD_VALUE_WITH_WEIGHT)/FieldValueWithWeight.cpp \
				$(FIELD_VALUE_WITH_WEIGHT)/set_accept.cpp \
				$(FIELD_VALUE_WITH_WEIGHT)/set_accept_encoding.cpp \
				$(FIELD_VALUE_WITH_WEIGHT)/set_accept_language.cpp \
				$(FIELD_VALUE_WITH_WEIGHT)/set_te.cpp

MAP_FIELD_VALUES_DIR = $(REQUEST_DIR)/MapFieldValues
SRCS		+=	$(MAP_FIELD_VALUES_DIR)/MapFieldValues.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_authorization.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_cache_control.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_cookie.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_host.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_keep_alive.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_range.cpp \
				$(MAP_FIELD_VALUES_DIR)/set_upgrade.cpp

MAP_SET_FIELD_VALUES_DIR = $(REQUEST_DIR)/MapSetFieldValues
SRCS		+=	$(MAP_SET_FIELD_VALUES_DIR)/MapSetFieldValues.cpp \
				$(MAP_SET_FIELD_VALUES_DIR)/set_forwarded.cpp \
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

VALUE_AND_MAP_FIELD_VALUES_DIR = $(REQUEST_DIR)/ValueAndMapFieldValues
SRCS		+=  $(VALUE_AND_MAP_FIELD_VALUES_DIR)/ValueAndMapFieldValues.cpp \
				$(VALUE_AND_MAP_FIELD_VALUES_DIR)/set_content_disposition.cpp

# IO
IO_DIR		=	IOMultiplexer
SRCS		+=	$(IO_DIR)/IOMultiplexer.cpp

# Server
SERVER_DIR	=	Server
SRCS		+=	$(SERVER_DIR)/Server.cpp

# Socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp

# StringHandler
STR_HANDLER	=	StringHandler
SRCS		+=	$(STR_HANDLER)/HttpMessageParser.cpp \
				$(STR_HANDLER)/HttpMessageParserIs.cpp \
				$(STR_HANDLER)/HttpMessageParserSkip.cpp \
				$(STR_HANDLER)/StringHandler.cpp

#HTTP Response
RESPONSE_DIR =	HttpResponse
SRCS		+=	$(RESPONSE_DIR)/HttpResponse.cpp \
				$(RESPONSE_DIR)/GET/get_directory_listing.cpp \
				$(RESPONSE_DIR)/GET/get_file_content.cpp \
				$(RESPONSE_DIR)/GET/get_request_body.cpp \
				$(RESPONSE_DIR)/DELETE/delete_target.cpp

# CgiHandler
CGI_DIR 	= $(RESPONSE_DIR)/CgiHandler
SRCS		+=	$(CGI_DIR)/CgiHandler.cpp


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes \
				$(SRCS_DIR)/$(REQUEST_DIR) \
				$(SRCS_DIR)/$(CONST_DIR) \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(IO_DIR) \
				$(SRCS_DIR)/$(SERVER_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR) \
				$(SRCS_DIR)/$(STR_HANDLER) \
				$(REQUEST_INCLUDES) \
				$(RESPONSE_INCLUDES) \
				$(SRCS_DIR)/$(CONFIG_DIR)/FileHandler \
				$(SRCS_DIR)/$(CONFIG_DIR)/ConfigParser \
				$(SRCS_DIR)/$(CONFIG_DIR)/Token \
				$(SRCS_DIR)/$(CONFIG_DIR)/Tokenizer \
				$(SRCS_DIR)/$(CONFIG_DIR) \
				$(SRCS_DIR)/$(CLIENT_SESSION_DIR) \
				$(SRCS_DIR)/$(CGI_DIR)

REQUEST_INCLUDES =	$(SRCS_DIR)/$(REQUEST_DIR) \
					$(SRCS_DIR)/$(DATE_DIR) \
					$(SRCS_DIR)/$(FIELD_VALUE_WITH_WEIGHT) \
					$(SRCS_DIR)/$(MAP_FIELD_VALUES_DIR) \
					$(SRCS_DIR)/$(MAP_SET_FIELD_VALUES_DIR) \
					$(SRCS_DIR)/$(MEDIA_TYPE_DIR) \
					$(SRCS_DIR)/$(MULTI_FIELD_VALUES_DIR) \
					$(SRCS_DIR)/$(SINGLE_FIELD_VALUE_DIR) \
					$(SRCS_DIR)/$(VALUE_AND_MAP_FIELD_VALUES_DIR) \
					$(SRCS_DIR)/$(REQUEST_DIR)/FieldValueBase \
					$(SRCS_DIR)/$(REQUEST_DIR)/RequestLine

RESPONSE_INCLUDES =	$(SRCS_DIR)/$(RESPONSE_DIR) \
					$(SRCS_DIR)/$(RESPONSE_DIR)/GET \
					$(SRCS_DIR)/$(RESPONSE_DIR)/POST \
					$(SRCS_DIR)/$(RESPONSE_DIR)/DELETE

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
	rm -f $(NAME) client

.PHONY	: re
re		: fclean all

.PHONY	: lint
lint	:
	python3 -m cpplint --recursive srcs \
	&& echo "\033[0;32mCPPLINT DONE\033[0m" \
	|| echo "\033[0;31mCPPLINT ERROR\033[0m"

.PHONY	: echo
echo	: CXXFLAGS += -D ECHO
echo	: re

.PHONY	: run_unit_test
run_unit_test	:
	#cmake -S . -B build
#	cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT -D ECHO"
	cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT -D ECHO -D DEBUG"
	cmake --build build
#	./build/unit_test 2>/dev/null
	./build/unit_test  # leaks report

.PHONY	: run_server_test
run_server_test	:
	cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT -D ECHO -D DEBUG"
	#cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT  -D ECHO"
	#cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG -D USE_SELECT"
	cmake --build build
	#./build/unit_test --gtest_filter=Server* 2>/dev/null
	#./build/unit_test --gtest_filter=*.ConnectClientCase1
	./build/unit_test --gtest_filter=Server*
	#./build/unit_test --gtest_filter=ServerUnitTest.TestMultiServer
	#./build/unit_test --gtest_filter=ServerUnitTest.ConnectClientCase*
	#./build/unit_test --gtest_filter=ServerUnitTest.ConnectClientCase1
	#./build/unit_test --gtest_filter=ServerUnitTest.ConnectClientCase2
#	./build/unit_test --gtest_filter=ServerUnitTest.ConnectMultiClient

.PHONY	: run_socket_test
run_socket_test	:
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Socket* 2>/dev/null

.PHONY	: run_result_test
run_result_test	:
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Result*

.PHONY	: run_errmsg_test
run_errmsg_test	:
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=ErrorMessage*

.PHONY    : run_request_test
run_request_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=HttpRequest*

.PHONY    : run_req_test
run_req_test    :
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=HttpRequestParser*

.PHONY    : run_string_test
run_string_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestStringHandler*:TestHttpMessageParser*

.PHONY    : run_rl_test
run_rl_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestRequestLine*

.PHONY    : run_single_field_value_test
run_single_field_value_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestSingleFieldValue*

.PHONY    : run_multi_field_values_test
run_multi_field_values_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMultiFieldValues*

.PHONY    : run_map_field_values_test
run_map_field_values_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMapFieldValues*

.PHONY    : run_map_set_field_values_test
run_map_set_field_values_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMapSetFieldValues*

.PHONY    : run_value_and_map_test
run_value_and_map_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestValueAndMapFieldValues*

.PHONY    : run_weight_test
run_weight_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestFieldValueWithWeight*

.PHONY    : run_media_test
run_media_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestMediaType*

.PHONY    : run_date_test
run_date_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestDate*

.PHONY    : run_file_test
run_file_test    :
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestFileHandler*

.PHONY    : run_token_test
run_token_test    :
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	#cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestTokenizer*

.PHONY    : run_parse_test
run_parse_test    :
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	#cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestParser*
	#./build/unit_test --gtest_filter=TestParser:TestParse
	#./build/unit_test --gtest_filter=TestParser.ParseServer

.PHONY    : run_config_test
run_config_test    :
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	#cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=TestConfig*

.PHONY    : run_get_test
run_get_test    :
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG -D UNIT_TEST"
	#cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=HttpResponseGET*


# include DEPS -----------------------------------------------------------------
-include $(DEPS)
