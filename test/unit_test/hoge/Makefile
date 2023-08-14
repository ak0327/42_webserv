NAME		=	a.out

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -g -fsanitize=address -fsanitize=undefined

SRC			=	test_main.cpp
OBJ			=	test_main.o


.PHONY	: all
all		: $(NAME)

$(NAME)	: $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

$(OBJ)	: $(SRC)
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY	: clean
clean	:
	rm -f $(OBJ)

.PHONY	: fclean
fclean	: clean
	rm -f $(NAME)

.PHONY	: re
re		: fclean all