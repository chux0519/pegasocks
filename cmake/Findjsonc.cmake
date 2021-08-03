# Try to find json-c
# Once done, this will define
#
# JSONC_FOUND         - system has jsonc
# JSONC_INCLUDE_DIRS - the jsonc include directories
# JSONC_LIBRARIES    - jsonc libraries directories

if(JSONC_INCLUDE_DIRS AND JSONC_LIBRARIES)
  set(JSONC_FIND_QUIETLY TRUE)
else()
  find_path(JSONC_INCLUDE_DIR json.h HINTS 
    /usr/local/include/json-c/ 
    /usr/include/json-c/)
  find_library(JSONC_LIBRARY json-c HINTS 
    /usr/local/lib
    /usr/lib/)

  set(JSONC_INCLUDE_DIRS ${JSONC_INCLUDE_DIR})
  set(JSONC_LIBRARIES ${JSONC_LIBRARY})

  # handle the QUIETLY and REQUIRED arguments and set JSONC_FOUND to TRUE if
  # all listed variables are TRUE
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(jsonc DEFAULT_MSG JSONC_INCLUDE_DIRS JSONC_LIBRARIES)

  mark_as_advanced(JSONC_INCLUDE_DIRS JSONC_LIBRARIES)
endif(JSONC_INCLUDE_DIRS AND JSONC_LIBRARIES)


