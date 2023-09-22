#include <string>
#include "gtest/gtest.h"
#include "Color.hpp"
#include "Error.hpp"
#include "Debug.hpp"
#include "Config/Config.hpp"
#include "Config/ErrorPage/ErrorPage.hpp"
#include "Config/HandlingString/ConfigHandlingString.hpp"
#include "Config/LocationConfig/LocationConfig.hpp"
#include "Config/ServerConfig/ServerConfig.hpp"

TEST(ConfigReading, Test1) {
	Config config_test("config/testconfig1.conf");
}
