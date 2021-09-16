cmake_minimum_required(VERSION 3.10)

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

file(GLOB SOURCES src/*.c 3rd-party/*.c 3rd-party/parson/parson.c)

include_directories(src)
include_directories(3rd-party)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(USE_MBEDTLS "Define if pegasocks should build with mbedtls instead of openssl" OFF)
option(USE_JEMALLOC "Define if pegasocks should build with jemalloc" OFF)
option(USE_STATIC "Define if static builds" OFF)
option(WITH_APPLET "Define if pegasocks with applet support" OFF)

execute_process(
    COMMAND
        git rev-parse --short HEAD
    RESULT_VARIABLE
        SHORT_HASH_RESULT
    OUTPUT_VARIABLE
        SHORT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE)

set(PGS_VERSION "\"v0.0.0-${SHORT_HASH}\"")

add_definitions(-DPGS_VERSION=${PGS_VERSION})

if(USE_STATIC)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  set(BUILD_SHARED_LIBS OFF)
  if(DEFINED APPLE)
    message(WARNING "Static build on Apple is not supported, see: https://developer.apple.com/library/archive/qa/qa1118/_index.html")
  else()
    set(CMAKE_EXE_LINKER_FLAGS "-static")
  endif()
endif()

if(USE_JEMALLOC)
  find_package(JeMalloc REQUIRED)
  include_directories(${JeMalloc_INCLUDE_DIRS})
  list(APPEND THIRDPARTY_LIBS JeMalloc::JeMalloc)

  message(STATUS "jemalloc include: ${JeMalloc_INCLUDE_DIRS}")
  message(STATUS "jemalloc lib: ${JeMalloc_LIBRARIES}")
endif()

find_package(Libevent2 REQUIRED)
include_directories(${LIBEVENT2_INCLUDE_DIR})
list(APPEND THIRDPARTY_LIBS ${LIBEVENT2_LIBRARIES})

if(USE_MBEDTLS)
  find_package(MbedTLS REQUIRED)
  add_definitions(-DUSE_MBEDTLS=1)

  message(STATUS "mbed TLS include: ${MBEDTLS_INCLUDE_DIR}")
  message(STATUS "mbed TLS lib: ${MBEDTLS_LIBRARIES}")
  include_directories(${MBEDTLS_INCLUDE_DIR})

  list(APPEND THIRDPARTY_LIBS ${LIBEVENT2_MBEDTLS_LIBRARIES} ${MBEDTLS_LIBRARIES})
else()
  find_package(OpenSSLx REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  list(APPEND THIRDPARTY_LIBS ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})
endif()

add_executable(pegas ${SOURCES} ./3rd-party/tray/tray.h)

if(WITH_APPLET)
add_definitions(-DWITH_APPLET=1)
if(UNIX AND NOT APPLE)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(APPINDICATOR REQUIRED appindicator3-0.1)
  include_directories(${APPINDICATOR_INCLUDE_DIRS})
  list(APPEND THIRDPARTY_LIBS ${APPINDICATOR_LIBRARIES})
endif(UNIX AND NOT APPLE)
if(APPLE)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DTRAY_APPKIT=1 -DOBJC_OLD_DISPATCH_PROTOTYPES=1 -framework Cocoa")
  # add app bundle
  set(BUNDLE_TARGET PegasApp)
  add_executable(${BUNDLE_TARGET} ${SOURCES} ./3rd-party/tray/tray.h)
  target_link_libraries(${BUNDLE_TARGET} pthread ${THIRDPARTY_LIBS})

  set_target_properties(${BUNDLE_TARGET} PROPERTIES
        MACOSX_BUNDLE ON
        MACOSX_BUNDLE_INFO_PLIST ${CMAKE_SOURCE_DIR}/distribution/macos/Info.plist.in)

  set(MACOSX_BUNDLE_BUNDLE_NAME "Pegas")
  set(MACOSX_BUNDLE_BUNDLE_VERSION "${SHORT_HASH}")
  set(MACOSX_BUNDLE_COPYRIGHT "Pegas is licensed under the BSD 3-Clause License")
  set(MACOSX_BUNDLE_GUI_IDENTIFIER "club.chux0519.hexyoungs")
  set(MACOSX_BUNDLE_ICON_FILE "AppIcon")

  file(COPY ${CMAKE_SOURCE_DIR}/distribution/macos/AppIcon.iconset DESTINATION ${CMAKE_BINARY_DIR})
  set(ICON_TARGET "${CMAKE_BINARY_DIR}/AppIcon.iconset")
  set(ICON_OUTPUT "${CMAKE_BINARY_DIR}/AppIcon.icns")

  add_custom_command(OUTPUT ${ICON_OUTPUT}
      COMMAND sips -z 16 16 ./iconx1024.png --out ${ICON_TARGET}/icon_16x16.png
      COMMAND sips -z 32 32 ./iconx1024.png --out ${ICON_TARGET}/icon_16x16@2x.png
      COMMAND sips -z 32 32 ./iconx1024.png --out ${ICON_TARGET}/icon_32x32.png
      COMMAND sips -z 64 64 ./iconx1024.png --out ${ICON_TARGET}/icon_32x32@2x.png
      COMMAND sips -z 128 128 ./iconx1024.png --out ${ICON_TARGET}/icon_128x128.png
      COMMAND sips -z 256 256 ./iconx1024.png --out ${ICON_TARGET}/icon_128x128@2x.png
      COMMAND sips -z 256 256 ./iconx1024.png --out ${ICON_TARGET}/icon_256x256.png
      COMMAND sips -z 512 512 ./iconx1024.png --out ${ICON_TARGET}/icon_256x256@2x.png
      COMMAND sips -z 512 512 ./iconx1024.png --out ${ICON_TARGET}/icon_512x512.png
      COMMAND cp iconx1024.png ${ICON_TARGET}/icon_512x512@2x.png
      COMMAND iconutil -c icns ${ICON_TARGET}
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/logo"
      )

    set(BUNDLE_RESOURCES ${ICON_OUTPUT} )
    list(APPEND BUNDLE_RESOURCES "${CMAKE_SOURCE_DIR}/logo/icon.png")
  set_target_properties(${BUNDLE_TARGET} PROPERTIES RESOURCE "${BUNDLE_RESOURCES}")
  target_sources(${BUNDLE_TARGET} PUBLIC ${BUNDLE_RESOURCES})
endif(APPLE)
endif(WITH_APPLET)

if(DEFINED DEBUG_EVENT)
  add_definitions(-DDEBUG_EVENT=1)
endif(DEFINED DEBUG_EVENT)

if (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Android")
  list(APPEND THIRDPARTY_LIBS pthread)
endif()
target_link_libraries(pegas ${THIRDPARTY_LIBS})
install(TARGETS pegas RUNTIME DESTINATION bin)
install(DIRECTORY logo DESTINATION share/pegasocks)

# tests
enable_testing()
add_subdirectory(test)


