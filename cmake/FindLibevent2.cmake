#
# https://github.com/sipwise/sems/blob/master/cmake/FindLibevent2.cmake
#
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
	FIND_PATH(LIBEVENT2_INCLUDE_DIR event2/event.h)

	list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .imp)
	list(INSERT CMAKE_FIND_LIBRARY_SUFFIXES 0 .imp.lib)

	if(CMAKE_CL_64)
		FIND_LIBRARY(LIBEVENT2_LIBRARIES NAMES libevent-x64-v120-mt-2_1_4_0 event libevent )
	else()
		FIND_LIBRARY(LIBEVENT2_LIBRARIES NAMES libevent-x86-v120-mt-2_1_4_0 event libevent )
	endif()
else()
	FIND_PATH(LIBEVENT2_INCLUDE_DIR event2/event.h HINTS /usr/include/event2 )

	# -levent -levent_core -levent_extra -levent_openssl
  # OpenBSD issue, lookup from /usr/local/lib to avoid lib mismatch
  FIND_LIBRARY(LIBEVENT2_LIBRARIES NAMES event libevent PATHS /usr/local/lib)
	FIND_LIBRARY(LIBEVENT2_CORE_LIBRARIES NAMES event_core libevent_core )
	FIND_LIBRARY(LIBEVENT2_EXTRA_LIBRARIES NAMES event_extra libevent_extra )
  FIND_LIBRARY(LIBEVENT2_SSL_LIBRARIES NAMES event_openssl libevent_openssl )
endif()


IF(LIBEVENT2_INCLUDE_DIR AND LIBEVENT2_LIBRARIES)
	SET(LIBEVENT2_FOUND TRUE)
ENDIF(LIBEVENT2_INCLUDE_DIR AND LIBEVENT2_LIBRARIES)

IF(LIBEVENT2_FOUND)
	IF (NOT Libevent2_FIND_QUIETLY)
		MESSAGE(STATUS "Found libevent2 includes:	${LIBEVENT2_INCLUDE_DIR}/event2/event.h")
		MESSAGE(STATUS "Found libevent2 library: ${LIBEVENT2_LIBRARIES}")
		MESSAGE(STATUS "Found libevent2 core library: ${LIBEVENT2_CORE_LIBRARIES}")
		MESSAGE(STATUS "Found libevent2 extra library: ${LIBEVENT2_EXTRA_LIBRARIES}")
    MESSAGE(STATUS "Found libevent2 openssl library: ${LIBEVENT2_SSL_LIBRARIES}")
	ENDIF (NOT Libevent2_FIND_QUIETLY)
ELSE(LIBEVENT2_FOUND)
	IF (Libevent2_FIND_REQUIRED)
		MESSAGE(FATAL_ERROR "Could NOT find libevent2 development files: ${LIBEVENT2_INCLUDE_DIR} :: ${LIBEVENT2_LIBRARIES}")
	ENDIF (Libevent2_FIND_REQUIRED)
ENDIF(LIBEVENT2_FOUND)

