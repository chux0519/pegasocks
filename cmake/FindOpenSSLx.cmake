if(DEFINED OpenSSLx_ROOT)
  set(OPENSSL_ROOT_DIR ${OpenSSLx_ROOT})
endif()
if (APPLE)
    # This is a bug in CMake that causes it to prefer the system version over
    # the one in the specified ROOT folder.
    if(NOT DEFINED OPENSSL_ROOT_DIR)
      execute_process (
          COMMAND sh -c "ls /usr/local/Cellar/openssl@1.1/ | sort -r |  grep -m1 1.1"
          OUTPUT_VARIABLE OPENSSL_VERSION
      )
      string(REGEX REPLACE "\n$" "" OPENSSL_VERSION "${OPENSSL_VERSION}")
      set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} /usr/local/Cellar/openssl@1.1/${OPENSSL_VERSION}/)
    endif()
    MESSAGE(STATUS "Found openssl library root: ${OPENSSL_ROOT_DIR}")
endif()
find_package(OpenSSL 1.1.0 REQUIRED)
MESSAGE(STATUS "Found openssl libraries: ${OPENSSL_LIBRARIES}")
