cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        src/client.c
        src/client.h
        src/connect.c
        src/connect.h
        src/packet.c
        src/packet.h
        src/publish.c
        src/publish.h
        src/subscribe.c
        src/subscribe.h
        src/unsubscribe.c
        src/unsubscribe.h)

add_executable(lwmqtt ${SOURCE_FILES})
