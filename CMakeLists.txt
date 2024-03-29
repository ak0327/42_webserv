cmake_minimum_required(VERSION 3.21)
project(webserv)

set(CMAKE_CXX_STANDARD 98)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -Werror -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fsanitize=address,undefined -fno-omit-frame-pointer")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D UNIT_TEST")

# LOCAL -----
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D DEBUG")
# -----------

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
        srcs/Client
        srcs/Event
        srcs/Config/FileHandler
        srcs/Config/ConfigParser
        srcs/Config/Token
        srcs/Config/Tokenizer
        srcs/Config
        srcs/Debug
        srcs/Error
        srcs/IOMultiplexer
        srcs/Server
        srcs/Session
        srcs/Socket
        srcs/StringHandler
        srcs/HttpResponse
        srcs/HttpResponse/Dynamic
        srcs/HttpResponse/CgiHandler
        srcs/HttpResponse/GET
        srcs/HttpResponse/POST
        srcs/HttpResponse/DELETE
        srcs/HttpRequest
        srcs/HttpRequest/Date
        srcs/HttpRequest/FieldValueBase
        srcs/HttpRequest/FieldValueWithWeight
        srcs/HttpRequest/MapFieldValues
        srcs/HttpRequest/MapSetFieldValues
        srcs/HttpRequest/MediaType
        srcs/HttpRequest/MultiFieldValues
        srcs/HttpRequest/RequestLine
        srcs/HttpRequest/SingleFieldValue
        srcs/HttpRequest/ValueWeightArraySet
        srcs/HttpRequest/ValueAndMapFieldValues

        test/unit_test/includes
)

# webserv_srcs -----------------------------------------------------------------
set(webserv_srcs
        srcs/Const/Constant.cpp
        srcs/Client/Client.cpp
        srcs/Event/Event.cpp
        srcs/Event/process_client_event.cpp
        srcs/Event/process_cgi_event.cpp
        srcs/Config/FileHandler/FileHandler.cpp
        srcs/Config/ConfigParser/ConfigParser.cpp
        srcs/Config/ConfigParser/http_block.cpp
        srcs/Config/ConfigParser/server_block.cpp
        srcs/Config/ConfigParser/location_block.cpp
        srcs/Config/ConfigParser/parse_timeout.cpp
        srcs/Config/ConfigParser/error_msg.cpp
        srcs/Config/Token/Token.cpp
        srcs/Config/Tokenizer/Tokenizer.cpp
        srcs/Config/Config.cpp
        srcs/Config/config_getter.cpp
        srcs/Debug/Debug.cpp
        srcs/Error/Error.cpp
        srcs/IOMultiplexer/IOMultiplexer.cpp
        srcs/Server/Server.cpp
        srcs/Server/process_event.cpp
        srcs/Server/timeout_manager.cpp
        srcs/Session/Session.cpp
        srcs/Socket/Socket.cpp
        srcs/StringHandler/StringHandler.cpp
        srcs/StringHandler/HttpMessageParser.cpp
        srcs/StringHandler/HttpMessageParserIs.cpp
        srcs/StringHandler/HttpMessageParserSkip.cpp
)

# request_srcs -----------------------------------------------------------------
set(http_request_srcs
        srcs/HttpRequest/HttpRequest.cpp
        srcs/HttpRequest/RequestLine/RequestLine.cpp
)

# Date
set(date_srcs
        srcs/HttpRequest/Date/Date.cpp
        srcs/HttpRequest/Date/set_date.cpp
)

# FieldValueBase
set(field_value_base_srcs
        srcs/HttpRequest/FieldValueBase/FieldValueBase.cpp
)

# FieldValueWithWeight
set(field_value_with_weight_srcs
        srcs/HttpRequest/FieldValueWithWeight/FieldValueWithWeight.cpp
        srcs/HttpRequest/FieldValueWithWeight/set_accept.cpp
        srcs/HttpRequest/FieldValueWithWeight/set_accept_encoding.cpp
        srcs/HttpRequest/FieldValueWithWeight/set_accept_language.cpp
        srcs/HttpRequest/FieldValueWithWeight/set_te.cpp
)

# MapFieldValues
set(map_field_values_srcs
        srcs/HttpRequest/MapFieldValues/MapFieldValues.cpp
        srcs/HttpRequest/MapFieldValues/set_authorization.cpp
        srcs/HttpRequest/MapFieldValues/set_cache_control.cpp
        srcs/HttpRequest/MapFieldValues/set_cookie.cpp
        srcs/HttpRequest/MapFieldValues/set_host.cpp
        srcs/HttpRequest/MapFieldValues/set_keep_alive.cpp
        srcs/HttpRequest/MapFieldValues/set_range.cpp
        srcs/HttpRequest/MapFieldValues/set_upgrade.cpp
)

# MapSetFieldValues
set(map_set_field_values_srcs
        srcs/HttpRequest/MapSetFieldValues/MapSetFieldValues.cpp
        srcs/HttpRequest/MapSetFieldValues/set_forwarded.cpp
        srcs/HttpRequest/MapSetFieldValues/set_link.cpp
        srcs/HttpRequest/MapSetFieldValues/set_via.cpp
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
        ${field_value_base_srcs}
        ${field_value_with_weight_srcs}
        ${map_field_values_srcs}
        ${map_set_field_values_srcs}
        ${media_type_srcs}
        ${multi_field_values}
        ${single_field_value_srcs}
        ${value_and_map_field_values_srcs}
)

list(APPEND webserv_srcs
        ${http_request_srcs}
)


# response_srcs ----------------------------------------------------------------
set(http_response_srcs
        srcs/HttpResponse/create_response_message.cpp
        srcs/HttpResponse/HttpResponse.cpp
        srcs/HttpResponse/Dynamic/Dynamic.cpp
        srcs/HttpResponse/Dynamic/cookie_login.cpp
        srcs/HttpResponse/Dynamic/session_login.cpp
)
# GET
set(get_srcs
        srcs/HttpResponse/CgiHandler/CgiHandler.cpp
        srcs/HttpResponse/GET/get_directory_listing.cpp
        srcs/HttpResponse/GET/get_file_content.cpp
        srcs/HttpResponse/GET/get_request_body.cpp
)

# POST
set(post_srcs
        srcs/HttpResponse/POST/post_target.cpp
)

# DELETE
set(delete_srcs
        srcs/HttpResponse/DELETE/delete_target.cpp
)

list(APPEND http_response_srcs
        ${get_srcs}
        ${post_srcs}
        ${delete_srcs}
)

list(APPEND webserv_srcs
        ${http_response_srcs}
)


# webserv_srcs -----------------------------------------------------------------
add_executable(webserv
        srcs/main.cpp
        ${webserv_srcs}
)

################################################################################
# unit_test_srcs ---------------------------------------------------------------
set (unit_test_srcs
        test/unit_test/TestError.cpp
        test/unit_test/TestResult.cpp
        test/unit_test/TestServer.cpp
        test/unit_test/TestSocket.cpp

        test/unit_test/TestStringHandler.cpp
        test/unit_test/TestFileHandler.cpp
        test/unit_test/TestTokenizer.cpp
        test/unit_test/TestParserFunc.cpp
        test/unit_test/TestParse.cpp
        test/unit_test/TestConfig.cpp

        test/unit_test/TestRequestLine.cpp

        # HttpMessageParser
        test/unit_test/HttpMessageParser/TestGet.cpp
        test/unit_test/HttpMessageParser/TestIs.cpp
        test/unit_test/HttpMessageParser/TestParse.cpp
        test/unit_test/HttpMessageParser/TestSkip.cpp
        test/unit_test/HttpMessageParser/TestStrToNum.cpp
        test/unit_test/TestHttpRequestParser.cpp

        # Date
        test/unit_test/Date/TestDate.cpp
        test/unit_test/Date/TestIfModifiedSince.cpp
        test/unit_test/Date/TestIfUnmodifiedSince.cpp
        test/unit_test/Date/TestLastModified.cpp

        # FieldValueWithWeight
        test/unit_test/FieldValueWithWeight/TestAccept.cpp
        test/unit_test/FieldValueWithWeight/TestAcceptEncoding.cpp
        test/unit_test/FieldValueWithWeight/TestAcceptLanguage.cpp
        test/unit_test/FieldValueWithWeight/TestTE.cpp

        # MapFieldValues
        test/unit_test/MapFieldValues/TestAltUsed.cpp
        test/unit_test/MapFieldValues/TestAuthorization.cpp
        test/unit_test/MapFieldValues/TestCacheControl.cpp
        test/unit_test/MapFieldValues/TestCookie.cpp
        test/unit_test/MapSetFieldValues/TestForwarded.cpp
        test/unit_test/MapFieldValues/TestHost.cpp
        test/unit_test/MapFieldValues/TestKeepAlive.cpp
        test/unit_test/MapFieldValues/TestProxyAuthorization.cpp
        test/unit_test/MapFieldValues/TestRange.cpp
        test/unit_test/MapFieldValues/TestUpgrade.cpp

        # MapSetFieldValues
        test/unit_test/MapSetFieldValues/TestLink.cpp
        test/unit_test/MapSetFieldValues/TestVia.cpp

        # MediaType
        test/unit_test/MediaType/TestContentType.cpp

        # MultiFieldValue
        test/unit_test/MultiFieldValues/TestAccessControlRequestHeaders.cpp
        test/unit_test/MultiFieldValues/TestContentEncoding.cpp
        test/unit_test/MultiFieldValues/TestContentLanguage.cpp
        test/unit_test/MultiFieldValues/TestIfMatch.cpp
        test/unit_test/MultiFieldValues/TestIfNoneMatch.cpp
        test/unit_test/MultiFieldValues/TestOrigin.cpp
        test/unit_test/MultiFieldValues/TestTransferEncoding.cpp

        # SingleFieldValue
        test/unit_test/SingleFieldValue/TestAccessControlRequestMethod.cpp
        test/unit_test/SingleFieldValue/TestConnection.cpp
        test/unit_test/SingleFieldValue/TestContentLength.cpp
        test/unit_test/SingleFieldValue/TestContentLocation.cpp
        test/unit_test/SingleFieldValue/TestExpect.cpp
        test/unit_test/SingleFieldValue/TestFrom.cpp
        test/unit_test/SingleFieldValue/TestMaxForwards.cpp
        test/unit_test/SingleFieldValue/TestReferer.cpp
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

        # ValueAndMapFieldValues
        test/unit_test/ValueAndMapFieldValues/TestContentDisposition.cpp

        # GET -> uncomment after implement GET
#        test/unit_test/HttpResponse/GET/TestAutoIndex.cpp
#        test/unit_test/HttpResponse/GET/TestCGI.cpp
        test/unit_test/HttpResponse/GET/TestGetInterpreter.cpp
        test/unit_test/HttpResponse/GET/TestGetRequestBody.cpp
        test/unit_test/HttpResponse/POST/TestPOST.cpp
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
