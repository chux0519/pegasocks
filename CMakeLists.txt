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

find_package(OpenSSLx REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

find_package(jsonc REQUIRED)
include_directories(${JSONC_INCLUDE_DIRS})

add_executable(pegas main.c ${SOURCES} ./3rd-party/tray/tray.h)

target_link_libraries(pegas ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES} ${JSONC_LIBRARIES} pthread)

if(DEFINED WITH_APPLET)
if(UNIX AND NOT APPLE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(APPINDICATOR REQUIRED appindicator3-0.1)
  include_directories(${APPINDICATOR_INCLUDE_DIRS})
  target_link_libraries(pegas ${APPINDICATOR_LIBRARIES})
endif()
if(APPLE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTRAY_APPKIT=1 -DOBJC_OLD_DISPATCH_PROTOTYPES=1 -framework Cocoa")
endif()
add_compile_definitions(WITH_APPLET=$WITH_APPLET)
endif(DEFINED WITH_APPLET)

install(TARGETS pegas RUNTIME DESTINATION bin)

# tests
enable_testing()
add_subdirectory(test)


