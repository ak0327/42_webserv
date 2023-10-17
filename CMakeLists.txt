cmake_minimum_required(VERSION 3.21)
project(webserv)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address,undefined -fno-omit-frame-pointer")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D DEBUG")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D USE_SELECT_MULTIPLEXER")

if(DEFINED CUSTOM_FLAGS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CUSTOM_FLAGS}")
endif()

# google test ------------------------------------------------------------------
include(FetchContent)
include(GoogleTest)

FetchContent_Declare(
        googletest
        DOWNLOAD_EXTRACT_TIMESTAMP true
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
enable_testing()


# when you .cpp or .hpp is added, add the following
#  include, webserv srcs, unit_test_srcs
# includes ---------------------------------------------------------------------
include_directories(
        includes
        srcs/Client
        srcs/Debug
        srcs/Error
        srcs/IOMultiplexer
        srcs/Server
        srcs/Socket
        srcs/Config
        srcs/Config/ConfigHandlingString
        srcs/Config/IsConfigFormat
        srcs/Config/AllConfig
        srcs/Config/IsConfigFormat
        srcs/Config/LocationConfig
        srcs/Config/ServerConfig
)

# webserv_srcs -----------------------------------------------------------------
set(webserv_srcs
        srcs/get_valid_config_file_path.cpp
        srcs/Client/Client.cpp
        srcs/Debug/Debug.cpp
        srcs/Error/Error.cpp
        srcs/IOMultiplexer/IOMultiplexer.cpp
        srcs/Server/Server.cpp
        srcs/Socket/Socket.cpp
        )

set(config_srcs
        srcs/HandlingString/HandlingString.cpp
        srcs/NumericHandle/NumericHandle.cpp
        srcs/Config/AllConfig/AllConfig.cpp
        srcs/Config/ConfigHandlingString/ConfigHandlingString.cpp
        srcs/Config/LocationConfig/LocationConfig.cpp
        srcs/Config/ServerConfig/ServerConfig.cpp
        srcs/Config/IsConfigFormat/IsConfigFormat.cpp
        srcs/Config/Config.cpp
)

add_executable(webserv
        srcs/main.cpp
        ${webserv_srcs}
        ${config_srcs}
        )

# unit_test_srcs ---------------------------------------------------------------
set (unit_test_srcs
        test/unit_test/is_valid_file_path/test_get_valid_config_file_path.cpp
        test/unit_test/TestConfig.cpp
        test/unit_test/TestError.cpp
        test/unit_test/TestResult.cpp
        test/unit_test/TestServer.cpp
        test/unit_test/TestSocket.cpp
        test/unit_test/TestIsConfigLineFormat.cpp
        test/unit_test/TestConfigReading.cpp
        test/unit_test/TestAddingUtils.cpp
)

add_executable(unit_test
        ${webserv_srcs}
        ${unit_test_srcs}
        ${config_srcs}
        )

# test -------------------------------------------------------------------------
target_link_libraries(
        unit_test
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(unit_test)
