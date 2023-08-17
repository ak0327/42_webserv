NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP


# SRCS -------------------------------------------------------------------------
SRCS_DIR	=	srcs

#main
SRCS		=	$(SRCS_DIR)/main.cpp


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJ			=	$(SRCS:%.cpp=%.o)
OBJS		=	$(addprefix $(OBJS_DIR)/, $(OBJ))


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes srcs/includes
INCLUDES	 =	$(addprefix -I, $(INCLUDES_DIR))


# RULES ------------------------------------------------------------------------
.PHONY	: all
all		: $(OBJS_DIR) $(NAME)

$(NAME)	: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(OBJS_DIR)		:
	@mkdir -p $@

$(OBJS_DIR)/%.o	: %.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<

.PHONY	: clean
clean	:
	rm -rf $(OBJ_DIR)

.PHONY	: fclean
fclean	: clean
	$(RM) $(NAME)

.PHONY	: re
re		: fclean all

.PHONY	: lint
lint	:
	cpplint --recursive srcs

.PHONY	: unit
unit	:
	./test/unit_test/run_unit_test.sh


-include $(DEPS)