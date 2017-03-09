cmake_minimum_required(VERSION 3.5)
project(lwmqtt)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(SOURCE_FILES
        packet/connect.c
        packet/connect.h
        packet/packet.c
        packet/packet.h
        packet/publish.c
        packet/publish.h
        packet/subscribe.c
        packet/subscribe.h
        packet/unsubscribe.c
        packet/unsubscribe.h
        client.c
        client.h)

add_executable(lwmqtt ${SOURCE_FILES})
