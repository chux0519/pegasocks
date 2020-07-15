cmake_minimum_required(VERSION 3.5)

project(pegasocks LANGUAGES C)

set (CMAKE_C_STANDARD 11)

# SAN start =======================================
set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel tsan asan lsan msan ubsan"
    FORCE)

# ThreadSanitizer
set(CMAKE_C_FLAGS_TSAN
    "-fsanitize=thread -g -O1"
    CACHE STRING "Flags used by the C compiler during ThreadSanitizer builds."
    FORCE)

# AddressSanitize
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)
# SAN end =======================================

file(GLOB SOURCES src/*.c 3rd-party/*.c)

include_directories(src)
include_directories(3rd-party)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(Libevent2 REQUIRED)
include_directories(${LIBEVENT2_INCLUDE_DIR})

find_package(OpenSSL 1.1.1 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

if(APPLE)
  set (CMAKE_C_FLAGS -I${OPENSSL_INCLUDE_DIR})
endif()

find_package(jsonc REQUIRED)
include_directories(${JSONC_INCLUDE_DIRS})

# utils
add_executable(http-client src/bin/http-client.c)
add_executable(hello-world src/bin/hello-world.c)
add_executable(hello-world-multi src/bin/hello-world-multi.c)
add_executable(json_parse src/bin/json_parse.c)
target_link_libraries(http-client ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})
target_link_libraries(hello-world ${LIBEVENT2_LIBRARIES})

find_package (Threads)
target_link_libraries(hello-world-multi ${LIBEVENT2_LIBRARIES} Threads::Threads)

target_link_libraries(json_parse ${JSONC_LIBRARIES})


add_executable(pegas main.c ${SOURCES})
target_link_libraries(pegas ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES} ${JSONC_LIBRARIES} Threads::Threads)

enable_testing()

add_subdirectory(test)


