NAME		=	a.out

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -MMD -MP
SANI_FLAGS	=	-g -fsanitize=address -fsanitize=undefined


# SRCS -------------------------------------------------------------------------
TEST_SRCS_DIR = .
TEST_SRCS	=	$(TEST_SRCS_DIR)/test_is_valid_file_path.cpp

PRJ_SRCS_DIR =	../../../srcs
PRJ_SRCS	=	$(PRJ_SRCS_DIR)/get_valid_config_file_path.cpp

SRCS		=	$(notdir $(TEST_SRCS)) $(notdir $(PRJ_SRCS))


# OBJS -------------------------------------------------------------------------
OBJS_DIR	=	objs
OBJS		=	$(SRCS:%.cpp=$(OBJS_DIR)/%.o)


# DEPS -------------------------------------------------------------------------
DEPS		=	$(OBJS:%.o=%.d)


# INCLUDES ---------------------------------------------------------------------
INCLUDES_DIR =	../../../includes
INCLUDES	 =	$(addprefix -I, $(INCLUDES_DIR))


# RULES ------------------------------------------------------------------------
.PHONY	: all
all		: $(OBJS_DIR) $(NAME)

$(OBJS_DIR)	:
	@mkdir -p $@

$(NAME)	: $(OBJS)
	$(CXX) $(CXXFLAGS) $(SANI_FLAGS) -o $@ $^

$(OBJS_DIR)/%.o: $(TEST_SRCS_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(SANI_FLAGS) $(INCLUDES) -c -o $@ $<

$(OBJS_DIR)/%.o: $(PRJ_SRCS_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(SANI_FLAGS) $(INCLUDES) -c -o $@ $<


.PHONY	: clean
clean	:
	rm -rf $(OBJS_DIR)

.PHONY	: fclean
fclean	: clean
	rm -f $(NAME)

.PHONY	: re
re		: fclean all

.PHONY	: run
run		:
	make all
	./$(NAME)
	make fclean

-include $(DEPS)
