cmake_minimum_required(VERSION 3.21)
project(webserv)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address,undefined -fno-omit-frame-pointer")

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D DEBUG")

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
        srcs/Debug
        srcs/Error
        srcs/HttpResponse
        srcs/IOMultiplexer
        srcs/Socket
)

# webserv_srcs -----------------------------------------------------------------
set(webserv_srcs
        srcs/get_valid_config_file_path.cpp
        srcs/Debug/Debug.cpp
        srcs/Error/Error.cpp
        srcs/HttpResponse/HttpResponse.cpp
        srcs/IOMultiplexer/IOMultiplexer.cpp
        srcs/HttpResponse/error_pages.cpp
        srcs/HttpResponse/GET/get_directory_listing.cpp
        srcs/HttpResponse/GET/get_cgi_result.cpp
        srcs/HttpResponse/GET/get_file_content.cpp
        srcs/HttpResponse/GET/get_request_body.cpp
        srcs/HttpResponse/DELETE/DeleteHttpResponse/DeleteHttpResponse.cpp
        srcs/HttpResponse/DELETE/StatusText/StatusText.cpp
        srcs/HttpResponse/DELETE/DeleteHttpResponse/get_location_path.cpp
        srcs/Socket/Socket.cpp
)

# httpresponse -----------------------------------------------------------------
# set(webserv_srcs
# srcs/Debug/Debug.cpp
# srcs/Error/Error.cpp
# )

add_executable(webserv
        srcs/main.cpp
        ${webserv_srcs}
        )

# unit_test_srcs ---------------------------------------------------------------
set (unit_test_srcs
        test/unit_test/is_valid_file_path/test_get_valid_config_file_path.cpp
        test/unit_test/TestError.cpp
        test/unit_test/TestResult.cpp
        test/unit_test/TestSocket.cpp
        test/unit_test/HttpResponse/TestAutoIndex.cpp
        test/unit_test/HttpResponse/TestCGI.cpp
        test/unit_test/HttpResponse/TestGetInterpreter.cpp
        test/unit_test/HttpResponse/TestGetRequestBody.cpp
        test/unit_test/TestInterpretPath.cpp
)

add_executable(unit_test
        ${webserv_srcs}
        ${unit_test_srcs}
        )

# test -------------------------------------------------------------------------
target_link_libraries(
        unit_test
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(unit_test)
