cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Werror")

add_subdirectory(lib/gtest/googletest)

include_directories(lib/gtest/googletest/include)

set(SOURCE_FILES
        src/client.c
        src/client.h
        src/helpers.c
        src/helpers.h
        src/packet.c
        src/packet.h
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
        tests/packet.cpp
        tests/macros.h
        tests/tests.cpp)

add_executable(tests ${TEST_FILES})

target_link_libraries(tests lwmqtt gtest gtest_main)
