NAME = webserve
CXX = c++
CXXFLAGS = -std=c++98 -Wall -Wextra -Werror

CONF_DIR = srcs/Config
UTILS_DIR = srcs/HandleString

#utils
SRCS_HandleString = $(UTILS_DIR)/HandlingString.cpp

# conに関するsrc
# SRCS_Conf = 

#socketに関する
#SRCS_Socket = $(SOCKET_DIR)/makeSockets.cpp $(SOCKET_DIR)/Socket.cpp

#http通信を実際に行うことに関する
#SRCS_Http = 

#test
SRCS_TestMain_HandlingString = srcs/TestMain/test_handlestring_main.cpp

#main
#SRCS_main += webserve_tentative/srcs/main.cpp

SRCS = $(SRCS_HandleString) $(SRCS_TestMain_HandlingString)

OBJS = $(SRCS:.cpp=.o)

all: $(NAME)

${NAME}:${OBJS}
	${CXX} ${OBJS} ${CXXFLAGS} -o ${NAME}

clean:
	rm -f $(OBJS)

fclean:clean
	rm -f $(NAME)

re: fclean all