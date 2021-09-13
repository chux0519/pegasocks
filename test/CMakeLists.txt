include_directories (${CMAKE_SOURCE_DIR}/3rd-party)
include_directories (${CMAKE_SOURCE_DIR}/src)

add_executable (pgs_util_test pgs_util_test.c 
                       ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
                       ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
                       ${CMAKE_SOURCE_DIR}/src/pgs_crypto.c)

add_executable (pgs_config_test pgs_config_test.c 
                       ${CMAKE_SOURCE_DIR}/src/pgs_config.c
                       ${CMAKE_SOURCE_DIR}/3rd-party/parson/parson.c
                       ${CMAKE_SOURCE_DIR}/src/pgs_log.c
                       ${CMAKE_SOURCE_DIR}/src/pgs_mpsc.c
                       ${CMAKE_SOURCE_DIR}/src/pgs_crypto.c)

if(USE_MBEDTLS)
  target_link_libraries (pgs_util_test ${MBEDTLS_LIBRARIES})
  target_link_libraries (pgs_config_test ${MBEDTLS_LIBRARIES})
else()
  target_link_libraries (pgs_util_test ${OPENSSL_LIBRARIES})
  target_link_libraries (pgs_config_test ${OPENSSL_LIBRARIES})
endif()

add_test (PegaUtilTests pgs_util_test)
add_test (PegaConfigTests pgs_config_test)
