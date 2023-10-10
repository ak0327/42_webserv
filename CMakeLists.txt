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

message(STATUS "CXX Flags: ${CMAKE_CXX_FLAGS}")

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
        srcs/Const
        srcs/Debug
        srcs/Error
        srcs/Socket
        srcs/StringHandler
        srcs/HttpRequest
        srcs/HttpRequest/FieldValues
        srcs/HttpRequest/LinkClass
        srcs/HttpRequest/RequestLine
        srcs/HttpRequest/SecurityPolicy
        srcs/HttpRequest/TwoValueSet
        srcs/HttpRequest/ValueArraySet
        srcs/HttpRequest/ValueDateSet
        srcs/HttpRequest/ValueMap
        srcs/HttpRequest/ValueSet
        srcs/HttpRequest/ValueWeightArraySet
)

# webserv_srcs -----------------------------------------------------------------
set(webserv_srcs
        srcs/get_valid_config_file_path.cpp
        srcs/Const/Constant.cpp
        srcs/Debug/Debug.cpp
        srcs/Error/Error.cpp
        srcs/Socket/Socket.cpp
        srcs/StringHandler/StringHandler.cpp
        srcs/StringHandler/HttpMessageParser.cpp
        srcs/HttpRequest/FieldValues/FieldValues.cpp
        srcs/HttpRequest/HttpRequest.cpp
        srcs/HttpRequest/HttpRequest_LinkClass.cpp
        srcs/HttpRequest/HttpRequest_SecurityPolicy.cpp
        srcs/HttpRequest/HttpRequest_TwoValueSet.cpp
        srcs/HttpRequest/HttpRequest_ValueArraySet.cpp
        srcs/HttpRequest/HttpRequest_ValueDateSet.cpp
        srcs/HttpRequest/HttpRequest_ValueMap.cpp
        srcs/HttpRequest/HttpRequest_ValueSet.cpp
        srcs/HttpRequest/HttpRequest_ValueWeightArraySet.cpp
        srcs/HttpRequest/RequestLine/RequestLine.cpp
        srcs/HttpRequest/TwoValueSet/TwoValueSet.cpp
        srcs/HttpRequest/ValueArraySet/ValueArraySet.cpp
        srcs/HttpRequest/ValueDateSet/ValueDateSet.cpp
        srcs/HttpRequest/ValueMap/ValueMap.cpp
        srcs/HttpRequest/ValueSet/ValueSet.cpp
        srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.cpp
        srcs/HttpRequest/SecurityPolicy/SecurityPolicy.cpp
        srcs/HttpRequest/LinkClass/LinkClass.cpp
)

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
        test/unit_test/TestHttpRequest.cpp
        test/unit_test/TestLeaks.cpp
        test/unit_test/TestHandlingString.cpp
        test/unit_test/TestHttpRequest_List.cpp
        test/unit_test/TestHttpRequest_TwoValueSet.cpp
        test/unit_test/TestHttpRequest_Array.cpp

        # add
        test/unit_test/TestStringHandler.cpp
        test/unit_test/TestHttpMessageParser.cpp
        test/unit_test/TestRequestLine.cpp
)

add_executable(unit_test
        ${webserv_srcs}
        ${unit_test_srcs}
        ${httprequest_unit_test}
)

# test -------------------------------------------------------------------------
target_link_libraries(
        unit_test
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(unit_test)
