NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP


# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

#main
SRCS		=	main.cpp \
				get_valid_config_file_path.cpp

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
	cpplint --recursive srcs

#.PHONY	: unit
#unit	:
#	./test/unit_test/run_unit_test.sh

.PHONY	: unit
unit	:
	#rm -rf build
	cmake -S . -B build
	cmake --build build
	#./build/unit_test 2>/dev/null
	./build/unit_test
	#cd build && ctest

-include $(DEPS)