NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP
CXXFLAGS	+=	-g -fsanitize=address,undefined -fno-omit-frame-pointer

# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

#main
SRCS		=	main.cpp \
				get_valid_config_file_path.cpp

#debug
DEBUG_DIR	=	Debug
SRCS		+=	$(DEBUG_DIR)/Debug.cpp


#error
ERROR_DIR	=	Error
SRCS		+=	$(ERROR_DIR)/Error.cpp

#io
IO_DIR		=	IOMultiplexer
SRCS		+=	$(IO_DIR)/IOMultiplexer.cpp

#HttpResponse
RESPONSE_DIR =	HttpResponse
SRCS		+=	$(RESPONSE_DIR)/HttpResponse.cpp \
				$(RESPONSE_DIR)/error_pages.cpp \
				$(RESPONSE_DIR)/GET/get_directory_listing.cpp \
				$(RESPONSE_DIR)/GET/get_cgi_result.cpp \
				$(RESPONSE_DIR)/GET/get_file_content.cpp \
				$(RESPONSE_DIR)/GET/get_request_body.cpp

RESPONSE_DELETE_DIR	= HttpResponse/DELETE
SRCS		+=	$(RESPONSE_DELETE_DIR)/DeleteHttpResponse/DeleteHttpResponse.cpp \
				$(RESPONSE_DELETE_DIR)/DeleteHttpResponse/get_location_path.cpp \
				$(RESPONSE_DELETE_DIR)/StatusText/StatusText.cpp

#socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(IO_DIR) \
				$(SRCS_DIR)/$(RESPONSE_DIR) \
				$(SRCS_DIR)/$(RESPONSE_DELETE_DIR)/DeleteHttpResponse \
				$(SRCS_DIR)/$(RESPONSE_DELETE_DIR)/StatusText \
				$(SRCS_DIR)/$(SOCKET_DIR)

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


.PHONY	: run_delete_test
run_delete_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=DeleteMethod*

.PHONY	: run_socket_test
run_socket_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=SocketUnitTest.*:SocketIntegrationTest.*

.PHONY	: run_interpret_path_test
run_interpret_path_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=Interpretpath*

.PHONY	: run_get_test
run_get_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=HttpResponseGET*


.PHONY	: run_autoindex_test
run_autoindex_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=*AutoIndex*

.PHONY	: run_cgi_test
run_cgi_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=*CGI*


-include $(DEPS)