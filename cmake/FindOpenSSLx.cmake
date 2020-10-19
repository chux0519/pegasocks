if (APPLE)
    # This is a bug in CMake that causes it to prefer the system version over
    # the one in the specified ROOT folder.
    set(OPENSSL_ROOT_DIR ${OPENSSL_ROOT_DIR} /usr/local/Cellar/openssl@1.1/1.1.1g/)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libcrypto.dylib CACHE FILEPATH "" FORCE)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_ROOT_DIR}/lib/libssl.dylib CACHE FILEPATH "" FORCE)
    set (CMAKE_C_FLAGS -I${OPENSSL_INCLUDE_DIR})
endif()
find_package(OpenSSL 1.1.0 REQUIRED)

