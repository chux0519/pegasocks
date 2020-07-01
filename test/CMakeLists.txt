include_directories (${CMAKE_SOURCE_DIR}/3rd-party)
include_directories (${CMAKE_SOURCE_DIR}/src)

add_executable (pgs_util_test pgs_util_test.c)
target_link_libraries (pgs_util_test
                       ${CMAKE_SOURCE_DIR}/3rd-party/sha3.c
                       ${CMAKE_SOURCE_DIR}/3rd-party/hash_32a.c
                       ${OPENSSL_LIBRARIES}
                       ${CMAKE_SOURCE_DIR}/src/pgs_util.c
                       )

add_test (PegaUtilTests pgs_util_test)


