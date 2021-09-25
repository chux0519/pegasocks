include_directories (${CMAKE_SOURCE_DIR}/3rd-party)
include_directories (${CMAKE_SOURCE_DIR}/include)

set(CONFIG_UTIL_SOURCES
    pgs_util_test.c 
    ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
    ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
)

set(CONFIG_TEST_SOURCES
    pgs_config_test.c 
    ${CMAKE_SOURCE_DIR}/src/core/config.c
    ${CMAKE_SOURCE_DIR}/src/core/log.c
    ${CMAKE_SOURCE_DIR}/src/core/mpsc.c
    ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
    ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
    ${CMAKE_SOURCE_DIR}/3rd-party/parson/parson.c
)

if(USE_MBEDTLS)
  set(CONFIG_UTIL_SOURCES
    ${CONFIG_UTIL_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/core/crypto_mbedtls.c
  )
  set(CONFIG_TEST_SOURCES
    ${CONFIG_TEST_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/core/ssl_mbedtls.c
    ${CMAKE_SOURCE_DIR}/src/core/crypto_mbedtls.c
  )
else()
  set(CONFIG_UTIL_SOURCES
    ${CONFIG_UTIL_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/core/crypto_openssl.c
  )
  set(CONFIG_TEST_SOURCES
    ${CONFIG_TEST_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/core/ssl_openssl.c
    ${CMAKE_SOURCE_DIR}/src/core/crypto_openssl.c
  )
endif()
add_executable (pgs_util_test ${CONFIG_UTIL_SOURCES})

add_executable (pgs_config_test ${CONFIG_TEST_SOURCES})

if(USE_MBEDTLS)
  target_link_libraries (pgs_util_test ${MBEDTLS_LIBRARIES})
  target_link_libraries (pgs_config_test ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_MBEDTLS_LIBRARIES} ${MBEDTLS_LIBRARIES})
else()
  target_link_libraries (pgs_util_test ${OPENSSL_LIBRARIES})
  target_link_libraries (pgs_config_test ${LIBEVENT2_LIBRARIES} ${LIBEVENT2_SSL_LIBRARIES} ${OPENSSL_LIBRARIES})
endif()

add_test (PegaUtilTests pgs_util_test)
add_test (PegaConfigTests pgs_config_test)
