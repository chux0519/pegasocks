cmake_minimum_required(VERSION 3.10)

project(pegasocks LANGUAGES C)

cmake_policy(SET CMP0074 OLD)

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

set(PEGAS_SOURCES 
                  src/pegas.c
                  src/config.c
                  src/mpsc.c
                  src/log.c
                  src/utils.c
                  src/codec/websocket.c
                  src/codec/trojan.c
                  src/codec/vmess.c
                  src/codec/shadowsocks.c
                  src/session/session.c
                  src/session/inbound.c
                  src/session/outbound.c
                  src/server/helper.c
                  src/server/local.c
                  src/server/manager.c
                  src/server/metrics.c
                  src/server/control.c
)


set(THIRDPARTY_SOURCES 3rd-party/parson/parson.c
                       3rd-party/hash_32a.c
                       3rd-party/sha3.c
)

include_directories(include)
include_directories(include/pegasocks)
include_directories(3rd-party)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(USE_MBEDTLS "Define if pegasocks should build with mbedtls instead of openssl" OFF)
option(USE_JEMALLOC "Define if pegasocks should build with jemalloc" OFF)
option(USE_STATIC "Define if static builds" OFF)
option(WITH_ACL "Define if pegasocks with acl support" OFF)
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

  set(PEGAS_SOURCES ${PEGAS_SOURCES}
                    src/ssl/mbedtls.c
                    src/crypto/mbedtls.c
  )
  list(APPEND THIRDPARTY_LIBS ${LIBEVENT2_MBEDTLS_LIBRARIES} ${MBEDTLS_LIBRARIES})
else()
  find_package(OpenSSLx REQUIRED)
  include_directories(${OPENSSL_INCLUDE_DIR})

  set(PEGAS_SOURCES ${PEGAS_SOURCES}
                    src/ssl/openssl.c
                    src/crypto/openssl.c
  )
  list(APPEND THIRDPARTY_LIBS ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})
endif()

if(WITH_ACL)
  find_package(PCRE REQUIRED)
  include_directories(${PCRE_INCLUDE_DIRS})
  list(APPEND THIRDPARTY_LIBS ${PCRE_LIBRARIES})

  set(PEGAS_SOURCES ${PEGAS_SOURCES}
                    src/acl.c
  )

  include_directories(3rd-party/libcork/include)
  include_directories(3rd-party/ipset/include)

  set(LIBCORK_SOURCE
        3rd-party/libcork/src/libcork/ds/array.c
        3rd-party/libcork/src/libcork/ds/buffer.c
        3rd-party/libcork/src/libcork/ds/managed-buffer.c
        3rd-party/libcork/src/libcork/ds/slice.c
        3rd-party/libcork/src/libcork/posix/process.c
        3rd-party/libcork/src/libcork/ds/hash-table.c
        3rd-party/libcork/src/libcork/core/hash.c
        3rd-party/libcork/src/libcork/ds/dllist.c
        3rd-party/libcork/src/libcork/core/allocator.c
        3rd-party/libcork/src/libcork/core/error.c
        3rd-party/libcork/src/libcork/core/ip-address.c
        )
  add_library(cork ${LIBCORK_SOURCE})

  set(LIBIPSET_SOURCE
        3rd-party/ipset/src/libipset/general.c
        3rd-party/ipset/src/libipset/bdd/assignments.c
        3rd-party/ipset/src/libipset/bdd/basics.c
        3rd-party/ipset/src/libipset/bdd/bdd-iterator.c
        3rd-party/ipset/src/libipset/bdd/expanded.c
        3rd-party/ipset/src/libipset/bdd/reachable.c
        3rd-party/ipset/src/libipset/set/allocation.c
        3rd-party/ipset/src/libipset/set/inspection.c
        3rd-party/ipset/src/libipset/set/ipv4_set.c
        3rd-party/ipset/src/libipset/set/ipv6_set.c
        3rd-party/ipset/src/libipset/set/iterator.c
        )

  add_library(ipset ${LIBIPSET_SOURCE})
  target_link_libraries(ipset cork)
  list(APPEND THIRDPARTY_LIBS ipset)

  add_definitions(-DWITH_ACL=1)
endif(WITH_ACL)


if(WITH_APPLET)
  set(PEGAS_SOURCES ${PEGAS_SOURCES}
                    src/applet.c
  )
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
    add_executable(${BUNDLE_TARGET} src/main.c ${PEGAS_SOURCES} ${THIRDPARTY_SOURCES})
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

add_library(libpegas ${PEGAS_SOURCES} ${THIRDPARTY_SOURCES})
set_target_properties(libpegas
    PROPERTIES
    OUTPUT_NAME "pegas"
    PUBLIC_HEADER "include/pegasocks/pegas.h"
)
target_link_libraries(libpegas ${THIRDPARTY_LIBS})
install(TARGETS libpegas
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/pegasocks
)

add_executable(pegas src/main.c)
target_link_libraries(pegas libpegas)

install(TARGETS pegas RUNTIME DESTINATION bin)
install(DIRECTORY logo DESTINATION share/pegasocks)

# manpage
find_program(A2X_EXECUTABLE NAMES a2x a2x.py)
if(NOT ${A2X_EXECUTABLE} STREQUAL A2X_EXECUTABLE-NOTFOUND)
  set(A2X_OPTS
    -D ${CMAKE_BINARY_DIR}
    -d manpage
    -f manpage
    )

  set(MAN_NAMES pegas.1)
  set(MAN_FILES)
  foreach(m IN LISTS MAN_NAMES)
    set(mf ${CMAKE_BINARY_DIR}/${m})
    set(ms ${CMAKE_SOURCE_DIR}/doc/${m}.asciidoc)
    add_custom_command(OUTPUT ${mf}
      COMMAND ${A2X_EXECUTABLE} ${A2X_OPTS} ${ms}
      DEPENDS ${ms}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      COMMENT "Building manpage ${mf}"
      VERBATIM)
    list(APPEND MAN_FILES ${mf})
  endforeach()
  add_custom_target(man ALL DEPENDS ${MAN_FILES})

  INSTALL(FILES ${MAN_FILES} DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
endif()

# tests
enable_testing()
add_subdirectory(test)

