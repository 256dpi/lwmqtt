cmake_minimum_required(VERSION 3.2.0)
project(lwmqtt)

add_subdirectory(gtest/googletest)
include_directories(gtest/googletest/include)

include(FetchContent)
FetchContent_Declare(cpr GIT_REPOSITORY https://github.com/libcpr/cpr.git GIT_TAG 67e12da316754ff3c6c91b50aafb2658438f3c1e) # the commit hash for 1.7.0
FetchContent_MakeAvailable(cpr)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic -Werror -Wno-unused-parameter -std=gnu++2a -std=c++2a")

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

add_library(lwmqtt_d SHARED ${SOURCE_FILES})

target_link_libraries(example-sync lwmqtt)


add_executable(example-async examples/async.c)

target_link_libraries(example-async lwmqtt pthread)

set(TEST_FILES
        tests_d/client.cpp
        tests_d/helpers.cpp
        tests_d/packet.cpp
        tests_d/string.cpp
        tests_d/tests.cpp)

add_executable(tests ${TEST_FILES})

target_link_libraries(tests lwmqtt gtest gtest_main ssl crypto)

set(TEST_FILES
        tests_ben/client.cpp
        tests_ben/tests.cpp)

add_executable(tests_app ${TEST_FILES})

target_link_libraries(tests_app lwmqtt gtest gtest_main)

set(TEST_FILES
        include/lwmqtt/unix.h
        ben_d/MQTTClient.cpp
        ben_d/CloudConnect.cpp
        ben_d/Socket.cpp
        ben_d/SSLConnection.cpp
        ben_d/main.cpp
        ben_d/mainAruba.cpp
        )

add_executable(ben ${TEST_FILES})

target_link_libraries(ben lwmqtt cpr::cpr ssl crypto ev)
