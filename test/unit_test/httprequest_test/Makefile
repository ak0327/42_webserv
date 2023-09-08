NAME		=	a.out

CXX			=	c++
CXXFLAGS	=	-std=c++98 -Wall -Wextra -Werror -g -fsanitize=address -fsanitize=undefined

SRC			=	request_test_main.cpp ../../../srcs/HandlingString/HandlingString.cpp
OBJ			=	request_test_main.o ../../../srcs/HandlingString/HandlingString.o


.PHONY	: all
all		: $(NAME)

$(NAME)	: $(OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@

request_test_main.o : request_test_main.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

../../../srcs/HandlingStringhandleString.o : ../../../srcs/HandlingString/HandlingString.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

.PHONY	: clean
clean	:
	rm -f $(OBJ)

.PHONY	: fclean
fclean	: clean
	rm -f $(NAME)

.PHONY	: re
re		: fclean all