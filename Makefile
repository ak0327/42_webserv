NAME 		=	webserv
CXX			=	c++

CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP

CXXFLAGS	+=	-g -fsanitize=address,undefined -fno-omit-frame-pointer
#CXXFLAGS	+=	-D USE_SELECT_MULTIPLEXER

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

#server
SERVER_DIR	=	Server
SRCS		+=	$(SERVER_DIR)/Server.cpp

#socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp

#numeric系の関数
NUMERIHANDLE_DIR =	NumericHandle
SRCS		+=	$(NUMERIHANDLE_DIR)/NumericHandle.cpp

#string系の関数
HANDLING_STR = HandlingString
SRCS		+=	$(HANDLING_STR)/HandlingString.cpp

#error
ERROR_DIR	=	Error
SRCS		+=	$(ERROR_DIR)/Error.cpp

#debug
DEBUG_DIR	=	Debug
SRCS		+=	$(DEBUG_DIR)/Debug.cpp

#socket
SOCKET_DIR	=	Socket
SRCS		+=	$(SOCKET_DIR)/Socket.cpp

#config
CONFIG_DIR	=	Config
SRCS		+=	$(CONFIG_DIR)/AllConfig/AllConfig.cpp \
				$(CONFIG_DIR)/ConfigHandlingString/ConfigHandlingString.cpp \
				$(CONFIG_DIR)/IsConfigFormat/IsConfigFormat.cpp \
				$(CONFIG_DIR)/LocationConfig/LocationConfig.cpp \
				$(CONFIG_DIR)/ServerConfig/ServerConfig.cpp \
				$(CONFIG_DIR)/Config.cpp

# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)

# todo: srcs/includes -> includes
INCLUDES_DIR = includes \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR) \
				$(SRCS_DIR)/$(CONFIG_DIR) \
				$(SRCS_DIR)/$(HANDRING_STR) \
				$(SRCS_DIR)/$(IO_DIR) \
				$(SRCS_DIR)/$(NUMERIHANDLE_DIR) \
				$(SRCS_DIR)/$(SERVER_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR)
INCLUDES	= $(addprefix -I, $(INCLUDES_DIR))


# CLIENT -----------------------------------------------------------------------
CLIENT_DIR	=	Client
CLIENT_SRC	=	$(CLIENT_DIR)/Client.cpp \
				$(CLIENT_DIR)/client_main.cpp
CLIENT_OBJ	=	$(CLIENT_SRC:%.cpp=%.o)
CLIENT_OBJS	=	$(addprefix $(OBJS_DIR)/, $(CLIENT_OBJ))

# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes \
				$(SRCS_DIR)/$(IO_DIR) \
				$(SRCS_DIR)/$(DEBUG_DIR) \
				$(SRCS_DIR)/$(ERROR_DIR) \
				$(SRCS_DIR)/$(SERVER_DIR) \
				$(SRCS_DIR)/$(SOCKET_DIR)

INCLUDES	 =	$(addprefix -I, $(INCLUDES_DIR))


# RULES ------------------------------------------------------------------------
.PHONY	: all
all		: $(NAME)

$(NAME)	: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJS_DIR)/%.o : $(SRCS_DIR)/%.cpp
	@mkdir -p $$(dirname $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

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
	python3 -m cpplint --recursive srcs

.PHONY	: run_unit_test
run_unit_test	:
	#rm -rf build
	cmake -S . -B build
	#cmake -S . -B build -DCUSTOM_FLAGS="-D USE_SELECT_MULTIPLEXER"
	cmake --build build
	./build/unit_test 2>/dev/null
	#./build/unit_test

.PHONY	: run_server_test
run_server_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	#cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG -D USE_SELECT_MULTIPLEXER"
	cmake --build build
	#./build/unit_test --gtest_filter=Server* 2>/dev/null
	./build/unit_test --gtest_filter=Server*
	#./build/unit_test --gtest_filter=*.ConnectClientCase1

.PHONY	: run_socket_test
run_socket_test	:
	#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Socket* 2>/dev/null

.PHONY	: run_result_test
run_result_test	:
	#rm -rf build
	cmake -S . -B build
	cmake --build build
	./build/unit_test --gtest_filter=Result*

.PHONY	: run_errmsg_test
run_errmsg_test	:
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

.PHONY	: run_config_test
run_config_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=ConfigReading*

.PHONY	: run_config_reading_test
run_config_reading_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=IsConfigLineTest*

.PHONY	: run_is_config_format_test
run_is_config_format_test :
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=IsConfigFormatTest*

.PHONY	: run_utils_test
run_utils_test :
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=UtilsTest*

.PHONY	: run_ready_config_test
run_ready_config_test	:
	#rm -rf build
	cmake -S . -B build -DCUSTOM_FLAGS="-D DEBUG"
	cmake --build build
	./build/unit_test --gtest_filter=ConfigReadingTest*

.PHONY	: client
client	: $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

-include $(DEPS)