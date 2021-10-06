include_directories (${CMAKE_SOURCE_DIR}/3rd-party)
include_directories (${CMAKE_SOURCE_DIR}/include)

set(CONFIG_UTIL_SOURCES
    pgs_util_test.c 
    ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
    ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
)

set(CONFIG_TEST_SOURCES
    pgs_config_test.c 
    ${CMAKE_SOURCE_DIR}/src/config.c
    ${CMAKE_SOURCE_DIR}/src/log.c
    ${CMAKE_SOURCE_DIR}/src/mpsc.c
    ${CMAKE_SOURCE_DIR}/src/utils.c
    ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
    ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
    ${CMAKE_SOURCE_DIR}/3rd-party/parson/parson.c
)

if(USE_MBEDTLS)
  set(CONFIG_UTIL_SOURCES
    ${CONFIG_UTIL_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/crypto/mbedtls.c
  )
  set(CONFIG_TEST_SOURCES
    ${CONFIG_TEST_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/crypto/mbedtls.c
  )
else()
  set(CONFIG_UTIL_SOURCES
    ${CONFIG_UTIL_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/crypto/openssl.c
  )
  set(CONFIG_TEST_SOURCES
    ${CONFIG_TEST_SOURCES}
    ${CMAKE_SOURCE_DIR}/src/crypto/openssl.c
  )
endif()
add_executable (pgs_util_test ${CONFIG_UTIL_SOURCES})

add_executable (pgs_config_test ${CONFIG_TEST_SOURCES})

if(USE_MBEDTLS)
  target_link_libraries (pgs_util_test ${MBEDTLS_LIBRARIES})
  target_link_libraries (pgs_config_test ${MBEDTLS_LIBRARIES})
else()
  target_link_libraries (pgs_util_test ${OPENSSL_LIBRARIES})
  target_link_libraries (pgs_config_test ${OPENSSL_LIBRARIES})
endif()

add_test (PegaUtilTests pgs_util_test)
add_test (PegaConfigTests pgs_config_test)
