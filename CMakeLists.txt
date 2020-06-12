cmake_minimum_required(VERSION 3.5)

project(ram LANGUAGES C)

set (CMAKE_C_STANDARD 99)

file(GLOB SOURCES src/*.c)

include_directories(src)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(Libevent2 REQUIRED)
include_directories(${LIBEVENT2_INCLUDE_DIR})

find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

# utils
add_executable(http-client src/bin/http-client.c)
add_executable(hello-world src/bin/hello-world.c)
add_executable(hello-world-multi src/bin/hello-world-multi.c)
target_link_libraries(http-client ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})
target_link_libraries(hello-world ${LIBEVENT2_LIBRARIES})

find_package (Threads)
target_link_libraries(hello-world-multi ${LIBEVENT2_LIBRARIES} Threads::Threads)


# cram
add_executable(cram main.c ${SOURCES})
target_link_libraries(cram ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})

