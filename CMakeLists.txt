cmake_minimum_required(VERSION 2.8.7)
project(lwmqtt)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c1x -D_POSIX_C_SOURCE=200112L -D_BSD_SOURCE -Wall")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Wall")
else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall")
endif()

add_subdirectory(lib/gtest/googletest)

include_directories(include)
include_directories(lib/gtest/googletest/include)

set(SOURCE_FILES
        include/lwmqtt.h
        include/lwmqtt/unix.h
        src/client.c
        src/helpers.c
        src/helpers.h
        src/packet.c
        src/packet.h
        src/os/unix.c)

add_library(lwmqtt ${SOURCE_FILES})

set(EXAMPLE_FILES example/main.c)

add_executable(example ${EXAMPLE_FILES})

target_link_libraries(example lwmqtt)

set(TEST_FILES
        tests/client.cpp
        tests/packet.cpp
        tests/tests.cpp)

add_executable(tests ${TEST_FILES})

target_link_libraries(tests lwmqtt gtest gtest_main)
