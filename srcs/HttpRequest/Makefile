NAME		=	a.out

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -g -fsanitize=address -fsanitize=undefined

SRC			=	HttpRequest.cpp Requestvalue_set.cpp test.cpp HandlingString.cpp
OBJ = $(SRC:.cpp=.o)

$(NAME)	: $(OBJ)
	$(CXX) $(OBJ) $(CXXFLAGS) -o $(NAME)

.PHONY	: clean
clean	:
	rm -rf $(OBJ)

.PHONY	: fclean
fclean	: clean
	rm -f $(NAME)