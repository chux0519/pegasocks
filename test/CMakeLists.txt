include_directories (${CMAKE_SOURCE_DIR}/src)

add_executable (crm_util_test crm_util_test.c)
target_link_libraries (crm_util_test
                       ${OPENSSL_LIBRARIES}
                       ${CMAKE_SOURCE_DIR}/src/crm_util.c)

add_test (CramUtilTests crm_util_test)


