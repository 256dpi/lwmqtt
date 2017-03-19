cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_subdirectory(lib/gtest/googletest)

include_directories(lib/gtest/googletest/include)

set(SOURCE_FILES
        src/client.c
        src/client.h
        src/connect.c
        src/connect.h
        src/helpers.c
        src/helpers.h
        src/identified.c
        src/identified.h
        src/packet.c
        src/packet.h
        src/publish.c
        src/publish.h
        src/string.c
        src/string.h
        src/subscribe.c
        src/subscribe.h
        src/unsubscribe.c
        src/unsubscribe.h)

add_library(lwmqtt ${SOURCE_FILES})

set(EXAMPLE_FILES
        example/main.c
        example/unix.c
        example/unix.h)

add_executable(example ${EXAMPLE_FILES})

target_link_libraries(example lwmqtt)

set(TEST_FILES
        tests/connect.cpp
        tests/macros.h
        tests/tests.cpp)

add_executable(tests ${TEST_FILES})

target_link_libraries(tests lwmqtt gtest gtest_main)
