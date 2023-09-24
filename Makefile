NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP
CXXFLAGS	+=	-g -fsanitize=address,undefined -fno-omit-frame-pointer

# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

#main
SRCS		=	main.cpp \
				get_valid_config_file_path.cpp

#error
ERROR_DIR	=	Error
SRCS		+=	$(ERROR_DIR)/Error.cpp

#debug
DEBUG_DIR	=	Debug
SRCS		+=	$(DEBUG_DIR)/Debug.cpp

#socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp

#handlestr
HANDLE_STR_DIR	=	HandlingString
SRCS		+= $(HANDLE_STR_DIR)/HandlingString.cpp

#httprequest
REQUEST_DIR	=	HttpRequest
SRCS		+=	$(REQUEST_DIR)/BaseKeyValueMap/BaseKeyValueMap.cpp \
				$(REQUEST_DIR)/HttpRequest/HttpRequest.cpp \
				$(REQUEST_DIR)/LinkClass/LinkClass.cpp \
				$(REQUEST_DIR)/RequestLine/RequestLine.cpp \
				$(REQUEST_DIR)/SecurityPolicy/SecurityPolicy.cpp \
				$(REQUEST_DIR)/TwoValueSet/TwoValueSet.cpp \
				$(REQUEST_DIR)/ValueArraySet/ValueArraySet.cpp \
				$(REQUEST_DIR)/ValueDateSet/ValueDateSet.cpp \
				$(REQUEST_DIR)/ValueMap/ValueMap.cpp \
				$(REQUEST_DIR)/ValueSet/ValueSet.cpp \
				$(REQUEST_DIR)/ValueWeightArraySet/ValueWeightArraySet.cpp


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR) \
				$(SRCS_DIR)/$(HANDLE_STR_DIR) \
				$(SRCS_DIR)/$(REQUEST_DIR)

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
	./build/unit_test 2>/dev/null
	#./build/unit_test

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
	./build/unit_test --gtest_filter=HandlingSTring*

-include $(DEPS)