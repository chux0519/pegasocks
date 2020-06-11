cmake_minimum_required(VERSION 3.5)

project(ram LANGUAGES C)

set (CMAKE_C_STANDARD 99)

file(GLOB SOURCES src/*.c)

include_directories(src)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(Libevent2 REQUIRED)
include_directories(${LIBEVENT2_INCLUDE_DIR})

add_executable(cram main.c ${SOURCES})

target_link_libraries(cram ${LIBEVENT2_LIBRARIES})

