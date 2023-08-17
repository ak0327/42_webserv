NAME		=	webserv

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP


# SRCS -------------------------------------------------------------------------
SRC_DIR		=	srcs

#main
SRCS		=	$(SRC_DIR)/main.cpp


# OBJS -------------------------------------------------------------------------
OBJ_DIR		=	objs
OBJ			=	$(SRCS:%.cpp=%.o)
OBJS		=	$(addprefix $(OBJ_DIR)/, $(OBJ))


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	includes srcs/includes
INCLUDES	 =	$(addprefix -I, $(INCLUDES_DIR))


# RULES ------------------------------------------------------------------------
.PHONY	: all
all		: $(NAME)

$(NAME)	: $(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $(NAME)

$(OBJ_DIR)/%.o : %.cpp
	@mkdir -p $$(dirname $@)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

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

-include $(DEPS)