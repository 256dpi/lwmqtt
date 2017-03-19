cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_subdirectory(lib/gtest)

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

set(EXAMPLE_FILES
        example/main.c
        example/unix.c
        example/unix.h)

set(TEST_FILES
        tests/tests.cpp)

add_executable(example ${SOURCE_FILES} ${EXAMPLE_FILES})

add_executable(tests ${SOURCE_FILES} ${TEST_FILES})

target_link_libraries(tests gtest gtest_main)
