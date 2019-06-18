#pragma once

#include <string.h>
#include <stdio.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define TEST_LOG(...) printf("%s: ", __FILENAME__); printf(__VA_ARGS__)

#define DEBUG_LOG(...) TEST_LOG(__VA_ARGS__)
