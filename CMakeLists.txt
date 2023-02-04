cmake_minimum_required(VERSION 3.14)
project(lwmqtt)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter")

include(FetchContent)
FetchContent_Declare(
        googletest # 1.13.0
        URL https://github.com/google/googletest/archive/b796f7d44681514f58a683a3a71ff17c94edb0c1.zip
        DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(googletest)

include_directories(include)

set(SOURCE_FILES
        include/lwmqtt.h
        include/lwmqtt/unix.h
        src/client.c
        src/helpers.c
        src/helpers.h
        src/packet.c
        src/packet.h
        src/string.c
        src/os/unix.c)

add_library(lwmqtt ${SOURCE_FILES})

add_executable(example-sync examples/sync.c)
target_link_libraries(example-sync lwmqtt)

add_executable(example-async examples/async.c)
target_link_libraries(example-async lwmqtt pthread)

set(TEST_FILES
        tests/client.cpp
        tests/helpers.cpp
        tests/packet.cpp
        tests/string.cpp
        tests/tests.cpp)

add_executable(tests ${TEST_FILES})
target_link_libraries(tests lwmqtt gtest gtest_main)
