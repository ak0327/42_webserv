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
        srcs/HttpRequest/FieldValueBase
        srcs/HttpRequest/LinkClass
        srcs/HttpRequest/RequestLine
        srcs/HttpRequest/TwoValueSet
        srcs/HttpRequest/MultiFieldValues
        srcs/HttpRequest/Date
        srcs/HttpRequest/MapFieldValues
        srcs/HttpRequest/SingleFieldValue
        srcs/HttpRequest/ValueWeightArraySet
        srcs/HttpRequest/MediaType
        srcs/HttpRequest/ValueAndMapFieldValues
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
)

# request_srcs -----------------------------------------------------------------

set(http_request_srcs
        srcs/HttpRequest/HttpRequest.cpp
        srcs/HttpRequest/HttpRequest_TwoValueSet.cpp
        srcs/HttpRequest/HttpRequest_ValueWeightArraySet.cpp
        srcs/HttpRequest/RequestLine/RequestLine.cpp
        srcs/HttpRequest/TwoValueSet/TwoValueSet.cpp
        srcs/HttpRequest/ValueWeightArraySet/ValueWeightArraySet.cpp
        srcs/HttpRequest/LinkClass/LinkClass.cpp
        srcs/HttpRequest/LinkClass/set_link.cpp
        )

# Date
set(date_srcs
        srcs/HttpRequest/Date/Date.cpp
        srcs/HttpRequest/Date/set_date.cpp
        )

# FieldValueBase
set(field_values_srcs
        srcs/HttpRequest/FieldValueBase/FieldValueBase.cpp
        )

# MapFieldValues
set(field_value_map_srcs
        srcs/HttpRequest/MapFieldValues/MapFieldValues.cpp
        srcs/HttpRequest/MapFieldValues/set_authorization.cpp
        srcs/HttpRequest/MapFieldValues/set_cache_control.cpp
        srcs/HttpRequest/MapFieldValues/set_cookie.cpp
        srcs/HttpRequest/MapFieldValues/set_forwarded.cpp
        srcs/HttpRequest/MapFieldValues/set_host.cpp
        srcs/HttpRequest/MapFieldValues/set_keep_alive.cpp
        srcs/HttpRequest/MapFieldValues/set_range.cpp
        srcs/HttpRequest/MapFieldValues/set_upgrade.cpp
        )

# MediaType
set(media_type_srcs
        srcs/HttpRequest/MediaType/MediaType.cpp
        srcs/HttpRequest/MediaType/set_media_type.cpp
        )

# MultiFieldValues
set(multi_field_values
        srcs/HttpRequest/MultiFieldValues/MultiFieldValues.cpp
        srcs/HttpRequest/MultiFieldValues/set_multi_field_values.cpp
        )

# SingleFieldValue
set(single_field_value_srcs
        srcs/HttpRequest/SingleFieldValue/SingleFieldValue.cpp
        srcs/HttpRequest/SingleFieldValue/set_single_field_value.cpp
        )

# ValueAndMapFieldValues
set(value_and_map_field_values_srcs
        srcs/HttpRequest/ValueAndMapFieldValues/ValueAndMapFieldValues.cpp
        srcs/HttpRequest/ValueAndMapFieldValues/set_content_disposition.cpp
        )

list(APPEND http_request_srcs
        ${date_srcs}
        ${field_value_map_srcs}
        ${field_values_srcs}
        ${media_type_srcs}
        ${multi_field_values}
        ${value_and_map_field_values_srcs}
        ${single_field_value_srcs}
        )

list(APPEND webserv_srcs
        ${http_request_srcs}
        )

# request_srcs -----------------------------------------------------------------

add_executable(webserv
        srcs/main.cpp
        ${webserv_srcs}
        )

################################################################################
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
        test/unit_test/TestRequestLine.cpp

        # http message parser
        test/unit_test/HttpMessageParser/TestIs.cpp
        test/unit_test/HttpMessageParser/TestSkip.cpp
        test/unit_test/HttpMessageParser/TestStrToNum.cpp

        # single field value
        test/unit_test/SingleFieldValue/TestAccessControlRequestMethod.cpp
        test/unit_test/SingleFieldValue/TestConnection.cpp
        test/unit_test/SingleFieldValue/TestContentLength.cpp
        test/unit_test/SingleFieldValue/TestExpect.cpp
        test/unit_test/SingleFieldValue/TestMaxForwards.cpp
        test/unit_test/SingleFieldValue/TestSecFetchDest.cpp
        test/unit_test/SingleFieldValue/TestSecFetchMode.cpp
        test/unit_test/SingleFieldValue/TestSecFetchSite.cpp
        test/unit_test/SingleFieldValue/TestSecFetchUser.cpp
        test/unit_test/SingleFieldValue/TestSecPurpose.cpp
        test/unit_test/SingleFieldValue/TestServiceWorkerNavigationPreload.cpp
        test/unit_test/SingleFieldValue/TestIfRange.cpp
        test/unit_test/SingleFieldValue/TestTrailer.cpp
        test/unit_test/SingleFieldValue/TestUpgradeInsecureRequests.cpp
        test/unit_test/SingleFieldValue/TestUserAgent.cpp

        # multi field value
        test/unit_test/MultiFieldValues/TestAccessControlRequestHeaders.cpp
        test/unit_test/MultiFieldValues/TestContentEncoding.cpp
        test/unit_test/MultiFieldValues/TestContentLanguage.cpp
        test/unit_test/MultiFieldValues/TestIfMatch.cpp
        test/unit_test/MultiFieldValues/TestIfNoneMatch.cpp
        test/unit_test/MultiFieldValues/TestTransferEncoding.cpp

        # map field values
        test/unit_test/MapFieldValues/TestAuthorization.cpp
        test/unit_test/MapFieldValues/TestCacheControl.cpp
        test/unit_test/MapFieldValues/TestCookie.cpp
        test/unit_test/MapFieldValues/TestForwarded.cpp
        test/unit_test/MapFieldValues/TestKeepAlive.cpp
        test/unit_test/MapFieldValues/TestProxyAuthorization.cpp
        test/unit_test/MapFieldValues/TestRange.cpp
        test/unit_test/MapFieldValues/TestUpgrade.cpp

        # value and map field values
        test/unit_test/ValueAndMapFieldValues/TestContentDisposition.cpp

        # date
        test/unit_test/Date/TestDate.cpp
        test/unit_test/Date/TestIfModifiedSince.cpp
        test/unit_test/Date/TestIfUnmodifiedSince.cpp
        test/unit_test/Date/TestLastModified.cpp

        # media type
        test/unit_test/MediaType/TestContentType.cpp
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
