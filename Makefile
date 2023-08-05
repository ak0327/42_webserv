NAME = webserv
CXX = c++
CXXFLAGS = -std=c++98 -Wall -Wextra -Werror -MMD -MP

DEPS = $(OBJS:%.o=%.d)
CONF_DIR = srcs/Config
UTILS_DIR = srcs/HandleString
OBJ_DIR = objs

#utils
SRCS_HandleString = $(UTILS_DIR)/HandlingString.cpp

# conに関するsrc
SRCS_Conf =  $(CONF_DIR)/Config.cpp $(CONF_DIR)/ServerConfig.cpp $(CONF_DIR)/LocationConfig.cpp $(CONF_DIR)/ErrorPage.cpp

#socketに関する
#SRCS_Socket = $(SOCKET_DIR)/makeSockets.cpp $(SOCKET_DIR)/Socket.cpp

#http通信を実際に行うことに関する
#SRCS_Http = 

#test
SRCS_TestMain_HandlingString = srcs/TestMain/test_handlestring_main.cpp
SRCS_TestMain_Config = srcs/TestMain/test_configread.cpp

#main
#SRCS_main += webserve_tentative/srcs/main.cpp

SRCS = $(SRCS_Conf) $(SRCS_HandleString) $(SRCS_TestMain_Config)

OBJ = $(SRCS:.cpp=.o)
OBJS = $(addprefix $(OBJ_DIR)/, $(OBJ))


all: $(NAME)

$(NAME):$(OBJS)
	$(CXX) $(OBJS) $(CXXFLAGS) -o $(NAME)

$(OBJ_DIR)/%.o : %.cpp
	@mkdir -p $$(dirname $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)

fclean:clean
	$(RM) $(NAME)

re: fclean all

-include $(DEPS)