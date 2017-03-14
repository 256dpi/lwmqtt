cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

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
        src/unsubscribe.h
        test/main.c
        test/unix.c
        test/unix.h)

add_executable(lwmqtt ${SOURCE_FILES})
